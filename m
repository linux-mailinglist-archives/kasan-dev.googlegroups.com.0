Return-Path: <kasan-dev+bncBCF5XGNWYQBRBIFOVKXAMGQE6RELPDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 085CF852107
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:09:38 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-360430193e9sf32255ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:09:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707775777; cv=pass;
        d=google.com; s=arc-20160816;
        b=KgCcHIcDpF2LriLmGexqUGM3+7BlzL8hwjeGNwVw8er+pGymvd/YYoINCjlPK6qjDI
         XKRbQxwPUmVAPgNky+4eKJQUtLSa0fn84OnqrbuMaJTXROczaV/yv38kZ7m6qlLzHITR
         Z/eApPnqR2YdUOSkdIKD1/TSOoojf9AiLvxZS8d+XGRkVrA2KrrVYCVx60UVNeZ63vCr
         EoddI8KgKXvfjed7/Zyxs/Ass9g14x4ykDO2TnkrPs4TFY5GxaJqCi1jUN/bxReX7ogr
         PFWKldfqCcMUN0nENXjZrShWZN2vfyDemw51gijI21v0yQesKvRBUS9bmkigUBYpaNhg
         V5Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=h+TnjPSBO6ccOTN51+hNJZHgLHyZf5uL/KMfY4vtLvQ=;
        fh=BiyvWE610p5ujQSW9Ua8GEGo4cDFbsOKPStIbq3l0AI=;
        b=jRxzIASJ1aCAx3jiOX6nc4XQy8/ZufzhRmi35uU9ACQGllqkFfjIIUWp8NKRz2QVS6
         9jXIfSEFctv96/lVHPixxn3y9rddcAWk+D5YohjUFRB6TlPl5apKFbN+TuBumYHbOswj
         gTBgkPthkfAC4FWbzdGHOHdBXSeNG+GqZfQd3RsOcghvVNM24mWZpre+J9tT7xTnNT0V
         EkRILlV2srDngdydLMqlBEBW6byrzA7P9+smJMHQq2WZGZenkTZbSGY+c2w3xqGmt/1b
         4w5tZuedPiWQgPlxFBERPADM2NHFB7MhMkJR9AD4G5OoZ/IR/dv9S+E2PmAQCvCTgRnr
         NuDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=dIS9WFhv;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707775777; x=1708380577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=h+TnjPSBO6ccOTN51+hNJZHgLHyZf5uL/KMfY4vtLvQ=;
        b=Via4BjwNVmgRCEH73h4yG61BArKmsK52TBaqx7Ppe/9CWe+GR7dirQlpVuNCcZEBlY
         Paj9KMtXOLBvqPYD7i8xV9fXb0cGB9sXmoCJXHJ1+xycbwO5fKdheyRR4re3epRmtA/l
         f8rDKSBv0C56g/g0PlsqoGauzC0hCUQE2Nxgvm5cNxFU8QvZxfm3YZb9HhzCdOuKhft+
         SBZv0N+wcZBzDkjASz7eVdSjSem7g8eJtWKZJL7ROHNSaI65CBKozCx9aDOFm5WnGGOz
         micgfrXPG3M5oILsZH5r+cJsS35kMvZmylQQdJqvtNTTPl3E42JUXuwtvWulY+wGTBMf
         5nEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707775777; x=1708380577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=h+TnjPSBO6ccOTN51+hNJZHgLHyZf5uL/KMfY4vtLvQ=;
        b=kG9wRkJT6DU8K8ffXdGaooquOU6qF2YwinU1UDL85xQYmp4YY0BPMyvM+canaz93Pm
         1w43SwjEvRGTM19lGa5RS+VvIJdIamBoQPejLA7tfOtasGOUrZnIYcyp1i619DLSJoDT
         Hjv9G4D6mHFvJzfeDNVfDWPwwmq+nqoZ14Ck0hHGTK69g3BR5DSdWkSVTisARs5JCYVI
         J7fasTl528P/YVCMY27ez9d1RA0YBO/06GXASPXW85e8N1YfKY1z4HO2uNmLLe54HkBQ
         frq39F3YsLNtBHZbTMZfBywMSeSgyCLSA05dtZCoFZmowZak25qV1rwrNOK5upOGeOOM
         u6Yg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLdSae0YLWuHNUCqxArVFnuvXCyUeLx8tpP3vGTL4xGW6BSe/pf8PP4uerTn3RXjjJWj8auFqcKhiwSmDHHeI5jMc/vmPyew==
X-Gm-Message-State: AOJu0YyW3YvNiwPDvZ21BEAy6/m6RPCdPAGNy1zAZFUs6PhXd7YBf00p
	AqAjBYRAWJm5FvIOkO91ZiYI7BYy5dGOzX7BkF84Bvqy0BJ0LY0G
X-Google-Smtp-Source: AGHT+IFctx/DD+SPMJg7+KJcsMXrFtTRrkQeKaxFM9vYniCVNjTYs/YX/Ver/LKqPKT7GkhpnSNIYQ==
X-Received: by 2002:a05:6e02:ef2:b0:363:befa:de2b with SMTP id j18-20020a056e020ef200b00363befade2bmr20779ilk.3.1707775776729;
        Mon, 12 Feb 2024 14:09:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2608:b0:363:d634:8952 with SMTP id
 by8-20020a056e02260800b00363d6348952ls2084490ilb.0.-pod-prod-08-us; Mon, 12
 Feb 2024 14:09:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVP3JEzNuXTg7kNuZnxpx/j3CvtmKVTPQm/NSijcZpVOwPF6fa5V481DJSr8KQAaUCIufM/L254EGedxtc7F3h2LSMC0fpyU8UEzw==
X-Received: by 2002:a5e:dc0b:0:b0:7c4:6158:f22e with SMTP id b11-20020a5edc0b000000b007c46158f22emr5436058iok.4.1707775776009;
        Mon, 12 Feb 2024 14:09:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707775775; cv=none;
        d=google.com; s=arc-20160816;
        b=TiTHwpHzlta5Cys5JKqeQ986sbLsO4OJldmzazR1qTn5c4nzK848cgo1APKU/4r3ql
         5bmX8N03ZVqrDCTa5+QlatmUx+J5BlXFhTJQkn8836WNHq+Q3brQNON/KIRm25ZxW1NK
         gANm/heoL1RAkW2fQ7G6EckC6UnIhA9axEi5Q2VhlgtUkJpjvC18K7OSP9pUkA9ZcIwD
         S2yVw/WNdKg62XVisQVOw3UsyYgCdxNoejXv+5JMBi5Dc85pUDorRs4kCBWyXeEQOUDw
         F6WOU0gUprRr2AIx5AtOIpUoivLTdqaEucL/VYQDaLzBnojAV8xmVxeXSCIligf8Rymm
         asIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ijXS7mVIfD783iJTrvPPuV7zXdag7eKduahqAMiyRM0=;
        fh=wSzNe8P89nMxix+JHBiT/wCt9iPL85B0NDICTvhExig=;
        b=mgj/j2eq9EsVH6kvOPKbulnx9XqYSvxfDaiOhYygxrpRQCAR7llhBFqt72yVuQ3lsr
         8C4xuQ20OZqQnfiRLRiPtQVtbDULsAAEv5tsfdYIeaNXHZ7hIuYTQPOia824D+PTIM7T
         qYqfYdGuQsE0wWVhWvRxiRXnwK44LVQ2Du3HJZ9NPv4FbfHmZoxEuIhHpUFzQ3ge1pvT
         cz+Ui/nYfBCbyfjsfHpuy81pnfYkbXBZtmu6c/XcPN+azAZQqaTFEn2a5P7rEcGV9AqB
         XM3XjfS+JDucqQjzfoPqzWNgbeERALHq+YbFWjqFFrSixnAKL3hh29rcPha0KArpg19F
         e3QA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=dIS9WFhv;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCU1mT7Spaun9aZydI0lWy6yk+ST1Rew+cPhURCk7cfoAxZaNpxkOkgoTzrN2cM7ElvJpS/JtR29/tm71dfrri5YehRp6rtEDxwhKg==
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id x18-20020a056602161200b007c473890eccsi10730iow.2.2024.02.12.14.09.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:09:35 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-5d8ddbac4fbso3290170a12.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:09:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVMIzo/WPDYf7qlaVAqxLs2raO/0Xv7w86vO8XNL8oSHzgPH7jcESCNe2YARSfbwJwrnQ106Q+Qapiplf0uOlpoxowysxjRleY/Lw==
X-Received: by 2002:a17:90a:fe94:b0:296:341b:a60 with SMTP id co20-20020a17090afe9400b00296341b0a60mr5675939pjb.13.1707775775367;
        Mon, 12 Feb 2024 14:09:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXFmq6skboMuhDnTKadtJfZgT9VX1O9l2W6KnbcMFAx9XdyxAvFZ92lXTXx+PzHE4VqB6Gb8gdfUY7ShKXc87iDYPu8iUFBsVQA4zljB8EL3NcQmCuCuAA2JelgKNNUiT7SGeSRbMw1CAkEQZQh8uIr/3yCXRfu0URp5QMkzy33/bBOfgmF174GjmWNhUxTZN9KW7hL6Wuz9XcP7ZOqqY9T8APP3Dzj+hlnrq/x80FRVBSKjpzzWq4rGduaKKRqY84J/xBOLgiPZfoMX/O9LG1WIxGEjdhuYFXLeePiqDFM4m5ec+oQPNzSPs67A0Pq4I+u7tmgWTQlYw8bu21gO+Re2X6ORhTDAr1nFzWyW9ISe3A4du9EqFYks/H2EzrJM9r6u6mbgIddw/dZWLYYYBryy8tlvIZztv+fBD81ucoYG04mFuJ8IKZ6/iWgmFDMk2KFStg+7P+IcWbeDisyDX8/F1rOIPWId4mqMswUXk01OialJQvzbbPylPS0pM30+1ibRCjh01YKDJP7sb0M3O/DTuiR5MBfdpfU89Ei5wnNpOhPAH/PIfy5pm+TwP8oMPZEM7dpiUbbr+EZ+jlMR7Id663Z68oZ5f54NesaeFe4vXqyhtxVHiS2EsU71HyOj3MUvF6a1RTq3C123haGXnVTCoWBlDgj88ZZGz6BrG9/HYPhhM7ZteimtFNLzh92MF4ReMz2OSnyJhPlwM3qoWrdUK1eOIXjh8fyhR3l9/gt4D0SMA9wD+X2X9U61OeMorAg/Bi+HrURV4sMgZHt7ReAsLkbiP4DCi61cOBHXwMfMF3wKqs3hVQOVYpp80nXuklgrj50oR4nz1zGjeYgpFIqA2h6+dWGdP8QVQ8yYJgoHZJUDrRnlGhZVyZ37ZINAAw5v5DFqSWyS8x3GbR3xlTibMvOOOkGucOAweVmpUa30Nfxgb8iFvPjw/1jKCgqdJ5RfI
 fekofFghndqS429qPijj99NgynM/9MTts72pIwdTyJJJrFpU3xt66RwdCnmb+HcZrzPZ5d9/PqoYYP/Ej/1qf6sU+jRLLI2MJHnp6vANQm1JGSFB+fEgvCamSmLPvl9I4j0cEejzGvhkiZ3j1FjtXjiSO4idmyUz3VsduHmX5tIrK12ZuQ70dZKShJz7qlL0KfrzRdYhD6PnNXfagcQnJ3JyGqCDtEbwb8U+BpqGp139+UWhxo93wCM2+G8xL9yAwjyWw9wfm9t9MLAeD/aJFOP7htwlOVFFvpz/afZJZEFecr4UnYiLSc+PDzZsnupIZMsTOgtnh3QYM3QF6TCpi8qnxUJxX7bM4KlrYrmwWyRjreJ7UKpegfmXbgwgOKlVovjZrMGpqPKRyfdviIoY9c5WzRyBUT5Z9d14q0YfA=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id qd4-20020a17090b3cc400b002967bc2c852sm1032925pjb.43.2024.02.12.14.09.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:09:35 -0800 (PST)
Date: Mon, 12 Feb 2024 14:09:34 -0800
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
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?iso-8859-1?Q?Tr=F8nnes?= <noralf@tronnes.org>
Subject: Re: [PATCH v3 01/35] lib/string_helpers: Add flags param to
 string_get_size()
Message-ID: <202402121408.5C98241E@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-2-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-2-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=dIS9WFhv;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52e
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

On Mon, Feb 12, 2024 at 01:38:47PM -0800, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> The new flags parameter allows controlling
>  - Whether or not the units suffix is separated by a space, for
>    compatibility with sort -h
>  - Whether or not to append a B suffix - we're not always printing
>    bytes.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

If there is a v4, please include some short examples with the .h bit
field documentation. It's pretty obvious right now but these kinds of
things have a habit of growing, so let's set a good example for
documenting the flags.

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121408.5C98241E%40keescook.
