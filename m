Return-Path: <kasan-dev+bncBCF5XGNWYQBRBQWGVKXAMGQE7GGBDFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 901BA852231
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 00:01:23 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-363e7f0c9dasf23878595ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 15:01:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707778882; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wg8aEq1DCi/EAQ6nbfMjVKF3J5FYsn1HjFlX6HaKFz/Nq0jW/pA7GRDuOLlXVXJEyG
         CYilPknLC0o7ZJqVTYmA8hJeKFFpP2yPm1AmzBvAtebF3vYpgOLyqZrSXEYzyeukSvbF
         b5lSTWP6ewJBCvMSgzz79/IwQ1UfJt97lfe3t+m7ydYvD9TD9gXNKNkofOU9CGUXdXmV
         4aDa5k3BN52JgLd7V3o18sErxkrdVL1BnSm3uVyyWuHJhVt7obRJY2aGdIToi2LuzpIo
         hcLwsLFMoDaXZOvX8tUQtkBuPKaNiCt2YzXSaTBVtQ9f+LEmmeiXyGE3yuOgfueZ4LIu
         wn6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4SOPAhznU9wvzOLrNLPTbnmHvOWWPpEE07ylCaTWs+0=;
        fh=fJQeOsGzytr7lxufFogxQt2h04SUt+dFcbhsAvGbMXc=;
        b=XQ7hdDSe6Js8+rnvaLDLTpzphxxlVJ6TGlhdiEnLzJsHQxdcQqXRr2b+MpVsNczqi3
         tqDOlC9BwCDMPv0wNIM1CKP2lB40pAI/PaQabvYPv4U7o+d1pINuX9Rk+N481bu/lLDq
         XJJGFiqgbcyUA83hbHCfRN/IMqnlTWQl7SfU5HzOg2oxWfHMym5WDixPvazi5HB1ZDIm
         yOWRDA85B4B5xJfsVmz0Pz4vRHVZUk28R96oIdZh+hWNLbZJz2Khek+T+beeX0SZC2wr
         Ot1P5pSH52JxVlqu9Gr363gf0YGO3XGkKI257A0DV/5bZmT0DG8c8Dh0vQpEXmAxn3TQ
         uPTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=kwdzvuQE;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707778882; x=1708383682; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4SOPAhznU9wvzOLrNLPTbnmHvOWWPpEE07ylCaTWs+0=;
        b=pLnk8F5iZOezQ+QtvZxnHi5aRCwQo3u599QfaWj0X9U3pso4dIf50EKjw78ZVe3A2S
         0wPtKr32xIjAn21dWxwp6wJn1WOsPUKMcSADrTq7pwjMCDLwMPFpq6GdR0krtsWCfqxz
         Ui59d3EqAFW+RZkixGrkKBSeEHbMzTCkIB5ODTR2jdUoLc4FrATgfJDenQ0ilP5eW80V
         QYQ1dDIUj4Ut5MIkJCXWRi/WB6eVMv4Gc9hd89z014XjFUf7IyN/iJITbK3d4zLCgVBy
         x8InhKFBc7EhsAgqTX2YjSOsmphOG0NuhIBeuZ4tBn8XFdtlZpmwdsb2VLFUlv1kxnXG
         xLAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707778882; x=1708383682;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4SOPAhznU9wvzOLrNLPTbnmHvOWWPpEE07ylCaTWs+0=;
        b=AL3zZglh9XA6o5KBOIsa5FUYyxomM9yYSkk5JfJcU/p62fU1JpYHljhhy3eetZ6FWl
         jDWAbxjNt2iVd5wmEGLaXv5/BprgnmGCyuRtvaVh/gIGd3AmpnrMu+wcvOP+D/IGrXgy
         2vbxi9RW2S9m3kY5LCLdD6M3QKFe8PQY4y+aEj6PeXXSFSverPbPpIVxa9oHdLS+RIxa
         RV+ITEV6Mtd9l1XCyVRUYfv3wDcoVPKs/6DaCDXTpUiPfe5RLya0JEhi7dyNnP0PY7Dw
         Ae7O9Lwq2l9M6oop/eB0wyiUOMX9XPuSfe+aP82XjNrf6WySomETaeGADwhujv5QJnJZ
         Tffw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVoAtquqtT/I2zj5yNKKlCxc0l7rt2aXK6C/zQLEQ1nZa+VQap1opQ2nF7oMs5jTVmSbSBxq2ubj0elE8iMxmxox/0fKy5lTA==
X-Gm-Message-State: AOJu0YyJ6safqdiJ0xhrWrNHigUgvG/y1bjXK4Rikpb+BLgg7HO3xZ7T
	Eu0WdZMECPmfXgX5PnqvzQLXV/pnqYPC+HBuUhYvNxJP5W1NjEUV
X-Google-Smtp-Source: AGHT+IH8KMmztbrC9/N+kFDBbwIPRK7fZ8iz8IugEWxgHUYX48ChJZ8aVrN7jDoQrSigEE5GoMllgQ==
X-Received: by 2002:a92:cd4e:0:b0:363:86da:6f69 with SMTP id v14-20020a92cd4e000000b0036386da6f69mr552195ilq.5.1707778882327;
        Mon, 12 Feb 2024 15:01:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3113:b0:363:846b:1132 with SMTP id
 bg19-20020a056e02311300b00363846b1132ls1239776ilb.0.-pod-prod-00-us; Mon, 12
 Feb 2024 15:01:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVvj/KBnrU/uBz02C+DNKkp989MJmimM51l3MfsHkCpoCktpFUasiGcLB33dS2ClJE9M/jxScedthR3u+xz0wgYN2Gl+DoSBwQZ2w==
X-Received: by 2002:a92:d4c7:0:b0:363:9213:f8db with SMTP id o7-20020a92d4c7000000b003639213f8dbmr496003ilm.7.1707778881612;
        Mon, 12 Feb 2024 15:01:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707778881; cv=none;
        d=google.com; s=arc-20160816;
        b=lqw+nEm1x4Gd68cCgTviZBb44Nx61b54N+nc6s8cVT07H4IRsrbVprbxxIspi78YGM
         instZz60zm53iqn8JwM6i6YJg8rgzp8adrM3JGf1yG6x9TFgEp6UHzTc/gOUYGmD5j+/
         zKI+XhY9vkel1vS0NMmH/bQqM31GyeWmU2DRB8TncLh7fzmxhbdf27WoyJWHtnekpTde
         HIgP2trsbq9faMYWBCTBnJMbctvmBtOj+35ew+e7SOdKpSqA6qEFv/N4l9kI17EHiBiQ
         7L9Nxp/qe465/eq8jiC6Ulfim44BtWp64HVG3EUwXkhdz+djoz8pG5fgb+2Y4jWLy536
         xwNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FzsjrPnusIaHUIYYiKKdbD1PNR9YsTLIdgA5piLTr48=;
        fh=AYspUhexU1GK1S8z2BZhRbAkO77rxEiK5JLrNGgsb/8=;
        b=aTb9wuKtZOI+/eOk/9Kc0bunFWLhclzd5wpF/ogBwnAT1dLkja6ou+/eWzRj+mYAjL
         RcQtlvwd3GEcKyUHQ+AFFSUo21n9vtZsuxFt+Wvc+HbW0BnfnclqrDO8boU/myjbCfaX
         dT4B34otMu3cNQQSldZblAMypUQVSvkst8/f7m4L5PjNQn4NMrMJH2PWDapYPifwzLLF
         sY8IEYyaD/FRcNOQK4tEt0+UWLr6uEeY3Y9F4AFkSCPsWKP4cMLs80EEId8BywSvkrqX
         mhBdE+xZWhB7Xi5dLWfWidJOOEeS8uc+dxcl0ZU20lcNqcr1b+j6mwzJqWo2goi32f4v
         SRew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=kwdzvuQE;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCXzyos9QcbPhMfiQM6L6itGEO3CwViDvUl9MmCFHkMR1emkeY+ipqi7tOib0qb6NVGDFkIyqixpv8gD1EPdFurJhlwX/wJnITCKHw==
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id a16-20020a92ce50000000b00363a9324ffcsi685355ilr.0.2024.02.12.15.01.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 15:01:21 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-6e08dd0fa0bso2545021b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 15:01:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUlXU3QkOrKnU1Z0nYshrPby/UVWlJJjjcWLg29TwKgwH+ddpSS/BAetnDXoVXI4C1oCTfdJLut1Dhu/Azd3tdwrBS2ghHHpUqX1A==
X-Received: by 2002:a05:6a00:4fd5:b0:6e0:e64d:8da2 with SMTP id le21-20020a056a004fd500b006e0e64d8da2mr1266121pfb.14.1707778880942;
        Mon, 12 Feb 2024 15:01:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU+qcXsHbes92+/irI/YGYifvLzoJkDUKEMtnSIFNvo1XUQdbfe93L4RVk2FqVnjfiFMzcJQXQtimnVaMtJMMpq/umqPU9l4XVgFW+rVJE5G3z/FWE2scEyApD2VHBH+eWpRVmKza3kHBcNTa4IJU+Tcck/xdWMqdP9Seehm+BA8QAtxWPMafz0/T4k1lAjzBfMxwPUzPnq/ajvxe5dE1HrqEJqH9HPJoIna6Ut/jaJtszsD0QrlyXvWHOkH2ZkoHaqjL/IEiigQlGGys8s0KW4UK/1QA2sUXHz1RGIEZXw5MeKGpLgEKFw+0pov+mTiOHnGIBggniQycKL7yAtxryybM99Cj5TkoUfQeSfZg5yyIyx2F6Ah1alGYZKUBBZ/ppNvR064Y8MYleXNzoRhlURCHT7B1KFPl/ctRNLROXxqaKmwiNYNVfsBPUzcXe+aimTQd/vgKJUBSlTmbhUwXFqhHUYLaW1X6qrLLWLMZR8vmRYv/lrvZy+8y+XLuGt7uPeJG79ULzoxlsUPJNALlLemBm4mPp9xt2G9geqhebf1EhRqFccpsF33YwtbadVDlZ4t1rjspc14Oac1XVpbS2tSSgVbYS5mHkIEzosdSbXVxoHvZB3gjviSe4i+YWWX10B+ubzOjB3KVLaiY1+D0EF5GO+ZM+zj3rJpNS4Na8DC0MiG3sWR1ha6Jk+mwDDRgz88w1Z0+nuVjb5nsov8AgvbvjT0zSM4l8hl6LZVMpUHEKVx3bopdtShQ7lPDbLvWAWAQYCmqHf9bUemNnbN5ZcV2EXpGI2CIKe9ZxjjdpDZnmWZ+HtBGKtDJVVjYTpqoihOKMxCiGi6Xt5monqQoBK3b3qdouhWGtKBV/x+2UVPLSGbF2827tlpPWGVFVIrDfHrnaWabFbAZUayEfuIzvxCBk1YAXz7kgryQMsrEkJjD0lLOvsM/mdjkGI218srU3Ivr
 r0B0Am0TQ1ODZbcBzYtsRKBYLc8wkWaeNd7CrG083I4A6o+6WcYDptaPx/9/r9YWji0F4F4kPyrdXD2Po/RENtfpE9Ujz87oAIsj9kg2tr6W1045vHMe0r47UDIIOhGTlnyuMkaLoeW3LBIVAZLLK0MyL5H0WMcHykkmGvZMEctaa45ndB9dXe8lR3GuLMCfOv3IedRdGdxvWF2xL1U7zC5W5Qq1lNuiX7zPKCAxOz5P1gXLfUPHs8KRPH+sawVe+jayky8u4XzYEyUY2wxGyxHK96tozTGtGo6CTRafrbshmzw0io4v1YURUMxJcbbCmETP2xGdXZFJu27l4R0SNb53nPJo9B0KdBR1PJXMeBo9W5L1ermy8pOsr46nPZbsqrmp0SYTpIPGXdUYARlw+sd148qd7B8HLK1krELA7lSt5f0danI2+1DRu6Gpg=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u33-20020a056a0009a100b006e0f7b8d15bsm143969pfg.185.2024.02.12.15.01.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 15:01:20 -0800 (PST)
Date: Mon, 12 Feb 2024 15:01:19 -0800
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
Subject: Re: [PATCH v3 22/35] mm/slab: enable slab allocation tagging for
 kmalloc and friends
Message-ID: <202402121500.68DFA4A32D@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-23-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-23-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=kwdzvuQE;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::430
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

On Mon, Feb 12, 2024 at 01:39:08PM -0800, Suren Baghdasaryan wrote:
> Redefine kmalloc, krealloc, kzalloc, kcalloc, etc. to record allocations
> and deallocations done by these functions.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

I'm not a big fan of the _noprof suffix, but anything else I can think
of isn't as descriptive, so:

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121500.68DFA4A32D%40keescook.
