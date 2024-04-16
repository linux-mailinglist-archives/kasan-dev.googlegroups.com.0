Return-Path: <kasan-dev+bncBDU3TMU54AGRBLVC7OYAMGQENZ4K6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15BD18A74A4
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Apr 2024 21:27:44 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1e2c0d3eadesf46879885ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Apr 2024 12:27:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713295662; cv=pass;
        d=google.com; s=arc-20160816;
        b=itSjuJdN+R1nhJ4kjnzhYxhFTUShKClobqLxMN7fsuIRQ+BYfoAMaTp6mfxb9Axxun
         XexxGenGje7kk1d/TZdIVgz7LMf0CswNDb7jwqFEe3DcTlT1MMcZWMNtPP3I2UEa75lm
         QHNrGTqfp1Snif9xMVhisOBW0U9raqRLqdvq2mTzlFb7UUal/Ft4m1B3D9q/IkCvbyp0
         wGOQclVe8K/q39/B4pk2xMZhwW0WVdt6z0VfXx+udsHm7hmHvDkKXj5GrRv7jzcpLsoO
         CZ6CbrAdABspTJG47V3/esMfT5cLSJP11ZaFO8tjNAmgjAyLN5RifujMlqbCtlJsZwEl
         zIQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3HDcIe2IeiyvxbHvk2tnC1ilj1GdikAmLOk+b8X/+f8=;
        fh=dqoamUKvPskw4hEp8cTndmYYvRzf4qxkLJUypdMoYt8=;
        b=a/qXJvhQKKHiY2Pa9o6Ya/xmTW6ex9k+eS6+YEBeNIqhJ9ITEWEnqn687CmVWM2ibI
         paDkQTindyXaJPrQq77hHkhuVIwZeHWZmmlKGHonMizgedSYI8xSVyvPwVSWT3uHojTZ
         EhjpqI5OZEaQWe6Nfy279uzTdoZeCJlg/7WmDOudrEXmKPZIihkO9bGAZxcprgeAbOvB
         Yg8JIk0vJhXGY5CQrU3kwvfnMMO99fHQE/Pgi010tuAPMgp4wU+FBcA1SQaikEtyBgJx
         Z/Utnj0+d0ZN+Xgxj4sE9m3JcdbUxz1RS8Mci0BhVBKIsIAxhYS4ldG6k4MUMVJrX8jo
         Ri9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="2/pZTcil";
       spf=pass (google.com: domain of 3lneezgskcyextzwf0ufsiflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--souravpanda.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3LNEeZgsKCYExtzwf0ufsiflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--souravpanda.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713295662; x=1713900462; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3HDcIe2IeiyvxbHvk2tnC1ilj1GdikAmLOk+b8X/+f8=;
        b=eIQSfMgR2FD/zVZqhhJ5KjcZeEfHldzcC+zNRi35c1xEWZTXYKyVCRTxQKzQBlmmfJ
         MC8w3kPaId8gYDyYPOEfQrvdYA0PaD4y869HkLpWcllG8wxOZVYKROvEfGBtsgyMMhcZ
         r9OgXdwW2OtNyj4zG+Kvg4l5m3iEXPLGF0A3MVukK+Rjtp3xoq88n8yqGUqUUA+sZ+2G
         DmhnmLGQZScYB6Xa7Yf9YSOUGQ48TSECa0vycOVhHHWRHdnp/ltMeJLKyPU2qdP+SifH
         Ptt5u2StuWuGxNGystJD3JbnZIo0vH/2k/eLW9fuUvLU6XxpODH0kS5FfVlzfrne/8rW
         czfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713295662; x=1713900462;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3HDcIe2IeiyvxbHvk2tnC1ilj1GdikAmLOk+b8X/+f8=;
        b=Hvu8mM8gWM6hAuvsZzntbFyGtia4nbtOQdeWgM8NpEARyn3PeYmnJJlbA8N6LDcWN5
         naCijfMTlPMlz3/F8xoO5IXmBgjdJC3K3ov5AgOukwXGk4g23shTHn0l8MHX/R6wM2Hx
         0muNlz9ZK+LKPKaSCWfF1z4GW1CLZan4WQCgEY00B9/yY78erKFYicm5H0QbeB71OiQ4
         TfRRF214ZKnoB5HpNCYqUC2b0WziDzivOqGk5zr743if40FDg3kWX/Xgwhep1x2NHJdz
         65xcbHnoVh0NGo0nLfdOkl54ZX/BZufG5ayJTJauH7RlPmkhVRPqM0gGieamuCINifXw
         qSGQ==
X-Forwarded-Encrypted: i=2; AJvYcCVP60J94la+AZg/G2Pk4tqmbmegK8bpod+x82O7UpRNDNuDeHTn0vhko04ZExnxT3eHq21PWzj4rEMvjuKoqIQHpd8ZVotmUg==
X-Gm-Message-State: AOJu0YzPv+9vM5oU6GEo+KoQrNxIG4s3A791HcPFjbKRLbEM8u/MgoDa
	5++iCDEAq457wMuqcMQh5Vnwgzb2d7hoSXv0wNAzU+onhOzI5h87
X-Google-Smtp-Source: AGHT+IEqGfV1S2DPHEKughFwQFDxeqZxQsjwoCgC50pzDBqui9Ra8ZoxgUfB2HO1uer2R3+kfIr02A==
X-Received: by 2002:a17:902:dac8:b0:1e4:ad9b:f770 with SMTP id q8-20020a170902dac800b001e4ad9bf770mr17122666plx.23.1713295662375;
        Tue, 16 Apr 2024 12:27:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e84e:b0:1e5:10f7:ff1e with SMTP id
 t14-20020a170902e84e00b001e510f7ff1els2890787plg.0.-pod-prod-01-us; Tue, 16
 Apr 2024 12:27:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvxJYXqaNTTrPoqkO3YU/m3b8L+VCSctX6tCuyGG/r7EdHapXfZSG8Ui3Cn4fQcgZBDSpfLxQQHvoimTwNeEro2UNtP//2Xs40tg==
X-Received: by 2002:a17:903:2452:b0:1e7:c05c:f1be with SMTP id l18-20020a170903245200b001e7c05cf1bemr4806008pls.0.1713295661127;
        Tue, 16 Apr 2024 12:27:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713295661; cv=none;
        d=google.com; s=arc-20160816;
        b=STQZEsTvIwM8HcrVzek1NGw8vxg1WCx3pBt8/WQ9+F/NmwTmjkkY30zXNLtwnBMZt4
         p/f+hWwR8Mu+MJECMq8/TeoH8cMkkG9HsMf69QoWiPmO1AagZHw/wv3vvjT+pNulblRD
         nkfA7CRuShEtRVLYN/iw5LE5nG3OE4aCHd4dQaPIid/CDPJCb6TaVJNmHE8FOw1SToWe
         zkeu+uBdYgyipt+PZ9Voh7KpBw17ICI577DIQ+96MrCDm8W+83Bq51nMjDrKtPKizTaf
         nuppg6pSdQ2eTigoVxWobhSKJ02dXN0ai0+Juz+UOBTU1H9hLAdiiXHt42yK/CNRGhgD
         9/8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KsLs5TwgQbCoTsIhV0PbmPPMuBa5UPbtwmIm4dUFoNk=;
        fh=Mbwc01QW7rgnP2uJd163ZEUxAzAKmuMZhT77rQOgucQ=;
        b=AZ7J15PmxnseNmqQ/fbrYUtn7o+8zWL/t64axGYCCSqWF9bTlEezIXU3LfcTwRzyhn
         h4XgildxFwGSaIcC1CgrUhlvS8gDcy0nwKQFkZ3LfomxZU+l9tkTIwr98SxjTpGKN/7H
         cHRy7FLJNZZlVE/CONn3GfMPAqwhdj1DtblAnyPi7N5gC0gr9AvCAWffWVM5LXdaxDzw
         fnL39SW05D9MyHiZHzaUiDGT5SrW6LhcsFypm0Fw0DweMIlHoRbHN81JOPPN279oA3d/
         cZewUKbdAWNTh0mbmOjFp/77PSihwNiS/dTNdu0K6o1b+GQcmrqFHJ+7asnjWYFugNv4
         SXHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="2/pZTcil";
       spf=pass (google.com: domain of 3lneezgskcyextzwf0ufsiflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--souravpanda.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3LNEeZgsKCYExtzwf0ufsiflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--souravpanda.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id p10-20020a170902f08a00b001dede653af6si712991pla.1.2024.04.16.12.27.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Apr 2024 12:27:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lneezgskcyextzwf0ufsiflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--souravpanda.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id 98e67ed59e1d1-2a5066ddd4cso4447948a91.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Apr 2024 12:27:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWF6Wn+U9IH3A0rtek3FalbzPI6tTq2WlDeW9K8B3zYDDOkKZactkjV3KPAOhyGSyVeHQC4sVGqu4jyMTbt7NOKC7SFUu9GVHiPbg==
X-Received: from souravbig.c.googlers.com ([fda3:e722:ac3:cc00:7f:e700:c0a8:3b3a])
 (user=souravpanda job=sendgmr) by 2002:a17:90b:3bc8:b0:2a2:8b25:745e with
 SMTP id ph8-20020a17090b3bc800b002a28b25745emr87242pjb.0.1713295660670; Tue,
 16 Apr 2024 12:27:40 -0700 (PDT)
Date: Tue, 16 Apr 2024 19:27:38 +0000
In-Reply-To: <20240321163705.3067592-31-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-31-surenb@google.com>
X-Mailer: git-send-email 2.44.0.683.g7961c838ac-goog
Message-ID: <20240416192738.3429967-1-souravpanda@google.com>
Subject: Re: [PATCH v6 30/37] mm: vmalloc: Enable memory allocation profiling
From: "'Sourav Panda' via kasan-dev" <kasan-dev@googlegroups.com>
To: surenb@google.com
Cc: 42.hyeyoo@gmail.com, akpm@linux-foundation.org, aliceryhl@google.com, 
	andreyknvl@gmail.com, arnd@arndb.de, axboe@kernel.dk, bristot@redhat.com, 
	bsegall@google.com, catalin.marinas@arm.com, cgroups@vger.kernel.org, 
	cl@linux.com, corbet@lwn.net, dave.hansen@linux.intel.com, dave@stgolabs.net, 
	david@redhat.com, dennis@kernel.org, dhowells@redhat.com, 
	dietmar.eggemann@arm.com, dvyukov@google.com, ebiggers@google.com, 
	elver@google.com, glider@google.com, gregkh@linuxfoundation.org, 
	hannes@cmpxchg.org, hughd@google.com, iamjoonsoo.kim@lge.com, 
	iommu@lists.linux.dev, jbaron@akamai.com, jhubbard@nvidia.com, 
	juri.lelli@redhat.com, kaleshsingh@google.com, kasan-dev@googlegroups.com, 
	keescook@chromium.org, kent.overstreet@linux.dev, kernel-team@android.com, 
	liam.howlett@oracle.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, masahiroy@kernel.org, mcgrof@kernel.org, 
	mgorman@suse.de, mhocko@suse.com, minchan@google.com, mingo@redhat.com, 
	muchun.song@linux.dev, nathan@kernel.org, ndesaulniers@google.com, 
	pasha.tatashin@soleen.com, paulmck@kernel.org, penberg@kernel.org, 
	penguin-kernel@i-love.sakura.ne.jp, peterx@redhat.com, peterz@infradead.org, 
	rientjes@google.com, roman.gushchin@linux.dev, rostedt@goodmis.org, 
	rppt@kernel.org, songmuchun@bytedance.com, tglx@linutronix.de, tj@kernel.org, 
	vbabka@suse.cz, vincent.guittot@linaro.org, void@manifault.com, 
	vschneid@redhat.com, vvvvvv@google.com, will@kernel.org, willy@infradead.org, 
	x86@kernel.org, yosryahmed@google.com, ytcoode@gmail.com, yuzhao@google.com, 
	souravpanda@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: souravpanda@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="2/pZTcil";       spf=pass
 (google.com: domain of 3lneezgskcyextzwf0ufsiflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--souravpanda.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3LNEeZgsKCYExtzwf0ufsiflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--souravpanda.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sourav Panda <souravpanda@google.com>
Reply-To: Sourav Panda <souravpanda@google.com>
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

> -void *__vcalloc(size_t n, size_t size, gfp_t flags)
> +void *__vcalloc_noprof(size_t n, size_t size, gfp_t flags)
>  {
>  	return __vmalloc_array(n, size, flags | __GFP_ZERO);
>  }
> -EXPORT_SYMBOL(__vcalloc);
> +EXPORT_SYMBOL(__vcalloc_noprof);

__vmalloc_array should instead be __vmalloc_array_noprof. This is because
we would want the more specific tag present in /proc/allocinfo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240416192738.3429967-1-souravpanda%40google.com.
