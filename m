Return-Path: <kasan-dev+bncBAABBAMY5XAAMGQERRLLZZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F904AADDFC
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 14:03:16 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-30c165885fdsf32833871fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 05:03:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746619395; cv=pass;
        d=google.com; s=arc-20240605;
        b=Yzgn9lzhjT0UG1bnrV4FhERrxiXYu+Xt0OeebqRmlgIczuabyDGmFqvwk4xDiukHRs
         41Rd64X72/D7+PhlFzpE2N84bq3KvQbvZGVnkAGzQBVav6GxEwV5I87bOya77VYaw6sS
         TGQLVb+9s2bp0zWVeTebSS1ixCgkMIHXXl6nM2fzK4geoyUABWYkAjYde/mYy3gva6tM
         nEIfGUGsKBkdBYPjj28DiF+SVglgjpsRoVStimL3ZAbNSAIyUHDF5b4j7kzQ4g9RmRCF
         RPgxqKkFkClWAhMf0LYr0gg0npwyFJjZxsC1kERjDVgIJnyr1BBsTh0tFglltaog/MmM
         S04g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kPOc7jV/pvkF99vajnZKEKp14KR7T35tNO8d58VwT0M=;
        fh=dHt3DUD4J8bBZSAcfC+d9/9f+zM4Z3+WQ7c8ISyDq2c=;
        b=Dj3mdCCjT7Ewa2ZO+AdRSjv+SgC1wFXvLrJRmYhqyY1YZ6zhayhGcJTohpMCstZBYm
         aJgs+mChlgJIeY1hJu8uBbAufuSEriy0PvDoQOS2wUjhIWw84WgiViKg99vtpbwfHeRI
         M3McJ+SC55S0XWFNWHL9uDb+dT8TZNflWyMlDyhwDKnUYlKPy0bwYIhoeFsPB8BAcxCU
         oMDR0YLb61ntUdeWcxOIDuL0NYOxSTRFlvFjOBhrhP8qq04CesiMZFrxFwXP1w0+XKm8
         IPfpyBPnIbt8oWDaz3JuGFVSFPQhRx8rjcd/Bt8GHVTotlr00Pa7DCJaf3l3nUAwKQaw
         gXmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DIzxHI8e;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746619395; x=1747224195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kPOc7jV/pvkF99vajnZKEKp14KR7T35tNO8d58VwT0M=;
        b=oJGYU1ezJDI6HmnBi3A6/wo/TMce/z8nen7aKJQrQr1BaFJXV21H+luvN2NAyFM5JT
         y9+eMVSz/lVDKs0TMcdWizLaCJPwIS0qs1PsaEZI/yvSqpmzPsvm4iTDWNv6w8VyByQm
         1l2M2sRGy4AY8KoA5tMMxfVxsJgvw9Ko/8/KI1bHQSybIQelTo4xKjDS409sjg1BG6lK
         D0WbVCMc8HaOB5/RykjP35xB5sL/AmMJ1su02f1+MFL/tgWWMUBYJBjWnwD/npPcUj3t
         t/5+TvTfsa2rPrYUie38jZVg+VFgiRC48EJUvG1I8BZoSk8y1om/kvxAJwl5EDNYuGVL
         Oshw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746619395; x=1747224195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kPOc7jV/pvkF99vajnZKEKp14KR7T35tNO8d58VwT0M=;
        b=c6zWaZekwWyFWfFzuG+OrQ5lAPTrCuk0JdoNGEwD93V5uzpTeou52BiKlwoxQh0t5J
         bBiV46TDBTsWLKiZakb1RrNs8WrjSqzoYcWOYjKdUBSC39BIvu8afxjVdRm7j1MWPw7F
         Tot4Ox7d1UShE5JWr8X2KJ68wT9TTFo7Q0vy2z7nZOX3vgBHRzG4dMWUONC+CV7D7XOb
         Orrzvl5MP9YNPOIx/DyuZOhlR6f3U3pzZVRjncyXczVosW4h8DRk/322DKziF56Nytaf
         hqk5DQ2Saz4v6pJj69GvS9Yai2jaOv2wJzqDHmgJVSy3eXPEhpr/QlxvOGpqI8He+22y
         VdDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUlHXPc5YP3fdifxgaq2jE21Wy/2faAgCAVo05KkbXAjk4TkL03hW6eiLVYtI2dhZI/QvVzWw==@lfdr.de
X-Gm-Message-State: AOJu0YxGp62MMGaZRnD4jHtOJHETkbS9WxZlnvFBpMPmPKfg+KZbhsKz
	VK8PT4bx/m6mgBnlQwfUCv36JT3FKV9LgLzF7Bdar4YhttzpE2DL
X-Google-Smtp-Source: AGHT+IHqWDIBD8Vzslc0CJ/BN0wQL1KyOaoheVCVVgpb+eEO1ZUUnbL3rpYo+hP+W9fWqSRu0mZbkg==
X-Received: by 2002:a2e:bcc6:0:b0:30b:ed8c:b1e7 with SMTP id 38308e7fff4ca-326ad1c9d51mr9386871fa.18.1746619393941;
        Wed, 07 May 2025 05:03:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH0NBWzSycmu+jMSap9skwzALiUt/S85CXmfkhumdk8Yw==
Received: by 2002:a2e:9054:0:b0:30d:8c55:9a50 with SMTP id 38308e7fff4ca-31f7a2a42cdls2387461fa.1.-pod-prod-07-eu;
 Wed, 07 May 2025 05:03:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWDiyk/AIqltGOEO7kP5d7VTc4E7175rmabcZrq8e17dThg9tGpp0lP+sqomwWrfqdRRNc07mTSBps=@googlegroups.com
X-Received: by 2002:a05:6000:2905:b0:3a0:847d:8326 with SMTP id ffacd0b85a97d-3a0b49b2468mr2392918f8f.25.1746619373083;
        Wed, 07 May 2025 05:02:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746619373; cv=none;
        d=google.com; s=arc-20240605;
        b=S3EuUhI6XONft9k/aoktduY4u27UzcA5ZjOmGXI4y81r+ZDuqYcYLXgosPdiHa/1nB
         FY5FEEFbbZcja+b4UcS29XWOY+NLD4z+8sOO9PS0zUD8dScqDqqmSTyqqP9XrWD+Z3Ql
         a+zkF7V3rIByMb3ALR9Wgu+4/i3YO3BvTpxb/9ROCM6WL7b/zfjs6zwCxHYy3YITGdvF
         WXpbPYor9Ch5qy9J+OSsWkBjESs1h0jebOCq/ZhnYz5sBAp0ufLevX7aMP/UJa1poQS3
         XDYr/dQIl4QkhM1yUz+pt3ES+3YRU9YA/9aC4xTjExyVD0qHL3DB9VtNQiIfIeMNU5XJ
         s3xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:dkim-signature:date;
        bh=lHpBgnMWGjdZKdQrg4rQ9wQFeDbCjxDr7o/BymUk+1Y=;
        fh=IuV6Sv7ZtjHemUvoM5T71MYysAqfuUvmt/9wfniPruc=;
        b=OxjwnTKPvrrKSpyUF5MZNKnIc0je6KVoNiNpoxZmCL6aCv80iKpZZrYg7HmSBfu3vL
         DmXywedTb6fli9IMq+GGKyCIZmWTQ/WT/TI7NiydaoGXuiv2w0W3GR/8DS4PKcaXJxl/
         k8LUgnAyB+Z2ozKL/M9YYayVXoqPQ5Cr6AtgKjIHRsXWhfWXj7kpoYQfkB0h9S/Gdt0k
         atoc3LHhCwadZOlJwmYkuzi/IJa9m7fKK1EjH8ViUJkvllMHhE2OcAvnwGDAAIEuW5jw
         3bSrpZ0cJLyRH0FI5wJjQLruqIBbgaViS4NOMRidgd2cpDwHnuHjQqkNfHUl0nqINoZx
         L9CQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DIzxHI8e;
       spf=pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta1.migadu.com (out-179.mta1.migadu.com. [2001:41d0:203:375::b3])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a099ae1537si238366f8f.2.2025.05.07.05.02.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 05:02:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of nicolas.schier@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) client-ip=2001:41d0:203:375::b3;
Date: Wed, 7 May 2025 14:02:42 +0200
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Nicolas Schier <nicolas.schier@linux.dev>
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com, llvm@lists.linux.dev
Subject: Re: [PATCH v3 0/3] Detect changed compiler dependencies for full
 rebuild
Message-ID: <20250507-mature-idealistic-toad-59c15f@l-nschier-aarch64>
References: <20250503184001.make.594-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250503184001.make.594-kees@kernel.org>
Organization: AVM GmbH
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: nicolas.schier@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DIzxHI8e;       spf=pass
 (google.com: domain of nicolas.schier@linux.dev designates
 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=nicolas.schier@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Sat, 03 May 2025, Kees Cook wrote:

>  v3: move to include/generated, add touch helper
>  v2: https://lore.kernel.org/lkml/20250502224512.it.706-kees@kernel.org/
>  v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kernel.org/
> 
> Hi,
> 
> This is my attempt to introduce dependencies that track the various
> compiler behaviors that may globally change the build that aren't
> represented by either compiler flags nor the compiler version
> (CC_VERSION_TEXT). Namely, this is to detect when the contents of a
> file the compiler uses changes. We have 3 such situations currently in
> the tree:
> 
> - If any of the GCC plugins change, we need to rebuild everything that
>   was built with them, as they may have changed their behavior and those
>   behaviors may need to be synchronized across all translation units.
>   (The most obvious of these is the randstruct GCC plugin, but is true
>   for most of them.)
> 
> - If the randstruct seed itself changes (whether for GCC plugins or
>   Clang), the entire tree needs to be rebuilt since the randomization of
>   structures may change between compilation units if not.
> 
> - If the integer-wrap-ignore.scl file for Clang's integer wrapping
>   sanitizer changes, a full rebuild is needed as the coverage for wrapping
>   types may have changed, once again cause behavior differences between
>   compilation units.

I am unsure if it is too much detail, but I'd like to see some of these 
infos in include/linux/compiler-version.h, too.

Kind regards,
Nicolas

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507-mature-idealistic-toad-59c15f%40l-nschier-aarch64.
