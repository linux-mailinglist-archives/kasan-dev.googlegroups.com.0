Return-Path: <kasan-dev+bncBCF5XGNWYQBRBFV7VKXAMGQEZJEXSVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id F1D3E8521AB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:45:43 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1d932efabe2sf145195ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:45:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707777942; cv=pass;
        d=google.com; s=arc-20160816;
        b=RC1FYpDgc3frS8TlJOKyTpAgLhGhfoYAS2SFnvxhpGrcQ95UR5/3604Uab20hJejgh
         nndqw6WFBbsq21I1RdwSjm9lBfAl8CQgZ/3PXvufCxT9R30rjVjYBixVhJQGbe930hHM
         iSmunMlpltuPkNtT8VppglhIZagjUyuDMoeWsX2TPT9kmAWPCu0y9QcbEgzp5JuAM4iS
         RN4PJyHgFMTo2mJsKPKcMsiHus4K931Opi/FZ3MxxIHIaYjQr4PKwnfFKXJh0PBFkgKe
         uRR9xBDtUy9weislLHNFvz0sgF1u1nEbODr1nXfMV3bzZQIFrtJQ85+kSs4EwHjAurwr
         IMmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=d+bCPCklnG3eVzndAirS9/T94/L942XdDujO/JJ179M=;
        fh=YqToy3jHhZeoP0rqJudFfHIdPvJ8l9NfqzWdicQ0Mrs=;
        b=I5aYE4GZAX0cf99+pzAr39sTftYYnbd9CO71PSa7TAZ3KrUK+j90XN/C1pSGHvWRT4
         tp65poFK4L66xZoBjyHqfi4KU6vHcPhLkq2IBejvA5KuCWVq1IhR6VEVSnbr5uSThI9U
         cXhRq/kFstE3aTUj+3kBC/smKRnQt16SrGrvWhv7+xYQWubZD+Kyd5ay3E6gMotHIb8n
         mRinBOJFclxlyYMcZFYMnqwI7QR7gfnmidDBMu46Tvq3UpBLvfsq3NXJtXd7KirRKpoD
         3xVH6vWJGzmBB6WPUOQJRLOEVw7lAjSNj+8qljiXYV+om37xJXQPbFD8vXJQQnhJ/fOX
         mqVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=UN+Oz70O;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707777942; x=1708382742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d+bCPCklnG3eVzndAirS9/T94/L942XdDujO/JJ179M=;
        b=eLqVTRx0hEsv/qwQjhhkdQ8ZJca8JbCQGDtJt8SYswY8U3Swmv+HzEqbrx81lVQbq2
         2HYHxL5wS/gGYD2dGbBVQ9nkfREeFH1uplGGIxTNazmfnjPGt36T0JQ7gBMw6NdKoNy3
         P8L02xmkdrSLvCRVoULQmLOrNs9nzlKC9634QrY7UHunU/cTgxTnZV8NSRWUdYk6Ac1G
         R6QGxFPJRmMYoEocfv23k4TJD7mxOyNwMG6TF7SwxWw4jlnfYFYf1W/N5WLLZHZC9m2W
         6IXgSrTwdJex0vxJP69W2n9QjjU35ZgUGUEx61jUqmLS5rdYAGNg16X0iySrpHya7cvY
         ms+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707777942; x=1708382742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d+bCPCklnG3eVzndAirS9/T94/L942XdDujO/JJ179M=;
        b=oue2WdEKDjVEpQJWXToiOd2Af7VP/FtZrkZwHy6CcE9C/+iTXy+gEBdIUT9rbs8e1g
         kZukZtDK0yK8BWp/IYvkeVPoGWBptK7sl/ZYEmVAZd1WTPTcRl8wvh5yuwIoD8Co20nT
         35BMLNVgOGwxPLg7Jg1AUos4oIytIF269xd0gWx7X8qducfBxcuEhDbkzRId1U5lrRX3
         cGDstWuZbSFJXyxOTna7v/voOeqkc2VZCj9nN6IOM18FLNaaZhqtJCyGLcQZy5kfBeC8
         lDUpALpBPpz1/jL0XGdawvPtz4mxdNSyWTAVjuiP9YrKAidfWcvGfkYeAwpfFBHG2X16
         SiKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyz8V5yvq3acq33GRKG89xz/G1sNoVTLNQdscacGPJpqPwgOB+7
	ZJMAfLSblU8YPwFl4QXfNbdFFAzt3Q0t3D1+DS6brIN903FSpJCK
X-Google-Smtp-Source: AGHT+IFO3IP+lrIqLxSp9FDzDe01dCG9LCQlFxZgt1/WiBWS3z3t8N9iY+UHaV9IcqNH3IyepKO3sQ==
X-Received: by 2002:a17:902:b18c:b0:1d9:7729:2a6c with SMTP id s12-20020a170902b18c00b001d977292a6cmr39301plr.16.1707777942623;
        Mon, 12 Feb 2024 14:45:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:554f:0:b0:59a:6de0:e6f5 with SMTP id e76-20020a4a554f000000b0059a6de0e6f5ls2283474oob.0.-pod-prod-02-us;
 Mon, 12 Feb 2024 14:45:42 -0800 (PST)
X-Received: by 2002:a4a:b502:0:b0:59d:4d95:f59d with SMTP id r2-20020a4ab502000000b0059d4d95f59dmr4442744ooo.9.1707777941808;
        Mon, 12 Feb 2024 14:45:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707777941; cv=none;
        d=google.com; s=arc-20160816;
        b=kNfnOC8A6PdzLuQQK59sIjvyf61tVWbHQj0/i6G5ya361hGqCnSNwsZ9FEuwIX92y8
         /JSVR3Ma60HDInSepHXh/5KUo7IVlzh7cCtywTqKum9dh7Mk0c6XGGyoZ6j49v+0YlMz
         UfDxPbiEFPhgP3XeyoLdLUSsq4VvutXitvjQ1dGXqgpLr95PBMzN1UQOS52NjFBI8fks
         0nuANd3JeFiU7tttLMdsRammaFb8lJ+PVdN0JqRY9RamSeQ1ruBT+e9G/sHDh5crNza7
         6jJqdA9xj6/BfB4hh08uX5MnaM37LGltfgxTpXdrXtD2QyYq/RyvEUHL7A+xCRcV+HSb
         gltQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=M9x0GXj1drWEZHiTvKM8aFvDBLB5BYp9bLGNurXOzwk=;
        fh=YqToy3jHhZeoP0rqJudFfHIdPvJ8l9NfqzWdicQ0Mrs=;
        b=VFi4LAOKZf1x1ecgbTGdJpwGadi5vivmoihjMDA8hsGp0lQBriu3E1AUQv3ZlYe1A/
         wG0+f9e5qJ8uQ2wsquTL96gWBNjliGaJCkoGmd3CfstN1T0V8VGyuZ/8xcNN4nEokC9I
         I36jfalz21eMaFUeKmLP5a07psjojzrlRGFp5MMN3qcnBP4Q8fyK9lf6bHcq8TmjHuKX
         uUfC+Yfl/4uiEIMAdhE4D8CfJO75nnv/46fOKcixo3tFkMU5v/ZagOIrkihG0aGwEmwW
         tK4v32Ak88JVLgdqLSbnLCHPwRGHqfcA9YRLPlQ7UqyqoNPTUgtdzkF4DGaRJmuZw4uN
         VXlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=UN+Oz70O;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCVCP0tshcowdlW5L+6aPWMBoHtIJya27PuwdRQgxT1ymKMBlgL1Te/oFny2ZuMz+nopVq1vap7oY3KjiE7QemnbO1QoqWPTjsIt+Q==
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id cb2-20020a0568201b8200b0059cf7f86428si130131oob.2.2024.02.12.14.45.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:45:41 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-6de3141f041so280363b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:45:41 -0800 (PST)
X-Received: by 2002:a05:6a21:1585:b0:19e:c777:5c6c with SMTP id nr5-20020a056a21158500b0019ec7775c6cmr5451544pzb.19.1707777941108;
        Mon, 12 Feb 2024 14:45:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXw9Gsf7ZI4ul2FjS6yiJvyc45dFQkJl5Huv68V6eExXnIssZsZwK67RcYY5UMcx7dXac0xIghB0mopjyodP1FNMOJF2IK1Q59DTWZVqRfHfJG1Ly/f72ohEQQptjh9mYs8IgHlP0RZgIrk8Fxi3glXjls295o1W497xhjSvqKdIbQQ838vPFGfAWvBpSRwAexqMSbYS1uSNR9H2P4PyDrioRkSn2McKPppcSQ4ksiDom6UrDw+qzJm1pcDiHDn36YTicu4Tb6OfBGIwNMC0YZS6jvtDzYyHMHjgWqNKOlMhcikODu4MUf1yQon9bEp/G60C94pD0AUOl5bFGHWelcCi2BQ9rbN01dxsEAmNAljZjrgJFel+dtn9eOd1DHbiSV3oyCZTzVb3z4+IOr76cU3qX3I0PIlGsizazr0DW9jRj8B2jYCx9jGaRAUgA9avMpLz8iHa/FTKQleKEDwrRxK89ZOcBTJvdB5pf89tH8BvCLndoxV6i16zKbujSt1I+OuqurzEfufj9Y2A4z77eMGdTOm4e1CnpOm7nFyKYELJzKw0effxdwGmY1kyZryOfIBcZUrsaH6BehoGHUbJoOH7s3BjvlS3iwpRKQRrX3QPMVoil4ps13PbMsj4S6gxIOhdiZzSmNdoMnfZ+hDOb1ODYDDdDNwmzqenTxtQfPqCEnheWBboOMaA8UA53AZKA5iXYLjfk2T6QNdT/IXLh+WaG0CXssltpNxvz05IKbqRcaiJALi4hKLZJC8G2oN2O9E2jhSXXgtcJjXob3jevmQ+618c9J0dM9gJg/Th09YbYlLl+91bJ2S1DenihfhYfGBuqBAFQvcB+xrT6nvtx6UeG2NzdHgvNeR+yuFzuSRUO7H2SaDhdjGA5/3jYyZ1U7Sd/WObY808ACZl0n9lSaJL0bKRYDU1+b/NrS+IujvlXqRZ/C1qKLYz1gQM84GDZT3hc
 V/4L9UFsRO7VBvzeYihsuzRzYrbBW3LkTbsjahtqMjg5OpUsARkQaJGZLEZzcadlgck5RuTuRietk3SqMWj20LtTNsa5/lAzCiqX+GJ90EHbSjcng3bPZ7o/mtDIPWhMVu2jvljCBqxWOnVXhwxJp1v0GiSZOj73RsBEH/X3lxZ9ynemE4ynFO9zDAgdtHAllvFi4DfOxzMb5O4HkYbVKzvKnIylxYfyHOPcyJUC+uGNtFqAzBOgQzv9pF3A6RSEH/5QVCb4yDB+WYfAY1kSeENtc4vUuOByGdfa6Qz2HNGvzBntetY35MjS+DoQxzqWNCfy+3jCFqlplV6XiRkRMqN/RP+4UkccJ/cxTIMpn8W/xK0bdI5t2HgodcMz3j+ITsEIl7SvsP3EKaAceUopwh8ONgL/prJfaHCC6fmQ4+1n8lJEJqkisImyMoQiQ=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ey7-20020a056a0038c700b006e0322f072asm6050101pfb.35.2024.02.12.14.45.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:45:40 -0800 (PST)
Date: Mon, 12 Feb 2024 14:45:40 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 33/35] codetag: debug: mark codetags for reserved
 pages as empty
Message-ID: <202402121445.B6EDB95@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-34-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-34-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=UN+Oz70O;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:39:19PM -0800, Suren Baghdasaryan wrote:
> To avoid debug warnings while freeing reserved pages which were not
> allocated with usual allocators, mark their codetags as empty before
> freeing.

How do these get their codetags to begin with? Regardless:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121445.B6EDB95%40keescook.
