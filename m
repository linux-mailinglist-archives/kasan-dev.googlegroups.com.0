Return-Path: <kasan-dev+bncBCC4R3XF44KBBNWHU2PAMGQEGE3BYSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A9B90674351
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 21:10:31 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id b23-20020a05651c033700b0028473c6cc7bsf676108ljp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 12:10:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674159031; cv=pass;
        d=google.com; s=arc-20160816;
        b=mFEq6ITH0akIEO5iwABE0Eu86jBgGSIPB0UnMRyo6WAwAkfCwAm8a9uWyBt6u9h81S
         1RZc+becmW5OJvPD3F3GGxKSuo1437iEWiYf+Vf6EGnBaS4AIqwsicQ1JMK0jPSfNGEQ
         SKpv7lhwyaZmV+0IBZ4OdRiRbKXjC8CPjKWRwJmJZJ8rE8ueL3LX2Qgj/sGOd3c6fxpD
         yhbdF51J6yH3Vlx0s3948XeQroWLEvGdd4XdTsLpoV2SS1UOVch4VshUg39k2p2O2t/G
         /Tmkbi42B9/hIx5UvRv9G7RmC7hGlgy4jFbY4uvQe9AK5uhbZU7zRY5oCFAoOf1vLpkt
         iRfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+Ftl6VVa2VfptT/p7SqN1CRr7cV+5N5uQjzI2FNylyM=;
        b=e+ogWe1DvfNqCwlYjB2RfWRt2jUq0VwdRE5CA/vY7TAVKqrae0U/O66VSffAvzEpp1
         FHiTTng9WVGmoz9+9VkNuRcDOrYq3KzSwmznq2z63Yl0cjH9R3Y3MRRJJArBgB2D3hDM
         McyLCxC5kA6chiPdManMpCEA08YXCYkUnDtKB5l7PFscSJE0CQfzQpFP+82PgaQnDiFs
         8WuuIz3KUxjpk7l1poaRcRVnbQh4vNeewQqsr4W4pde5Ul7+9+lVN722+l3VlV9v9ZmV
         o12qXwCl+topkl+Mp0nMWn5xwtnmOzP4dvYDhxtbw6Vknx5MzzlhAwKs29pWUxmQOBfZ
         nqng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qELc81M9;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+Ftl6VVa2VfptT/p7SqN1CRr7cV+5N5uQjzI2FNylyM=;
        b=BeK73zgK6wR1PHUj9DRvgHCHd6pWED8bvgFQ5ytJGTY+h7j30RUPN/LGMZ3vFpJzHL
         GvR6pFafClPod6HLnw6xTtkW2ZbU0C0COu478qsf2B4Exq9LjibRqhyJeIWlsZqErniA
         Jg0TmPSm+MQvc7ulLCHC7xLmTXnkXl7HJgge5JTF0ufhX/4Xjv/QlvnoWzHU0+QrDfTD
         Y5scUKZQm3EUpLQ+3y2c3k1JTR6xsZim9Dsoo9U9xDoiKa4Ou3z+PDbJMVu7cKe2FxHT
         pW/BuN7bze9kZlSEs+BbW+oo9Dd3FVjKhmOTC84QE5qeN0vg5t/mtp5IEP9h6LVRDvO3
         vupw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+Ftl6VVa2VfptT/p7SqN1CRr7cV+5N5uQjzI2FNylyM=;
        b=yIGLes1D3SvLL2W34IIk0sJBZ1PzPhbZy+Uap6mEllgqwFpx+GCDTRfpG71ZegdQtL
         CqAu1IYlJq3f7lRFE1NwPgcLQ9tyJwN4EEq8gvj5EX7Q/JCrkzb5w7oGk7LPtJU2Meij
         nJepWijLRv3909AAalJTE9vWijNRUtdTrm9oyQN1gdfXIeMfLxYSP57weYSXxoQsUHTA
         fL18515lB7wZB7dv7Dsx/gWFOVirEsHccByP/Sqy0fqslCxjWTKGDV8M9lXtbzpXeCfk
         gmtpNCrF3vOs5TF0iYetHo6B3Zzr7TGNi03ZmrOLoHTQFiWGl6yBbsCPgW26KpC9nSu4
         Wzig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koiuGwlp73/EKvtwmJjALzVKSCPU75AZ8jpZOU3dzMO5+9JuljJ
	F4+rfeyRW8keLp0TehJesGc=
X-Google-Smtp-Source: AMrXdXvw4pCoq4lvrSB5ShocyFT3bJ/bKGytHVW94pc2/Lb27ldRHuFsfbnQTCO02PfyyR52IszlpA==
X-Received: by 2002:a05:6512:3051:b0:4b5:918a:51f9 with SMTP id b17-20020a056512305100b004b5918a51f9mr1453230lfb.649.1674159030723;
        Thu, 19 Jan 2023 12:10:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls1959999lfr.3.-pod-prod-gmail; Thu, 19
 Jan 2023 12:10:29 -0800 (PST)
X-Received: by 2002:a05:6512:b04:b0:4cc:7258:f178 with SMTP id w4-20020a0565120b0400b004cc7258f178mr8532529lfu.59.1674159029498;
        Thu, 19 Jan 2023 12:10:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674159029; cv=none;
        d=google.com; s=arc-20160816;
        b=wG0YaJ5Q285/13ZPEn0Q1tXuGvBAFrV8DPgCyW/B0qFAF4SLYrh3VjsxOVIyXoY0Wn
         uvzXtLJcEITrQzR5gOswp6DSo/0COqNSAAOkiX18K9T1x1ECJ0GV3blBjSIaDhgAeBgo
         xBzXa36ZFoa8w+Eo7TgMkZt4hJwe6V7RYCo4OoRGwRfBNM7tEpk/ZsRNUHiMgYPQhzQQ
         XPJrB0N4uQ79vYXI0a97Q8+eaK3pAXYCSJAMrexN4BWO1+vLsfCezR/u+JKNbHKOYO7a
         6BtzTqWSbQshjKW6MSa8KoXfveuNItP/24P+rsSu9u4Rs6K2auAjiyqXTsaHR28NOrln
         RXUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LXbWHFWuV7YhKVy8Snv69h+Bejyq4VAQXeDQ8Uyq7a0=;
        b=u1an+1q1RwMy2fOuBV/8okpUx9DjMdLMSmVO5RfLftY2Z98DZUNcinm4sq9qZ6OwdR
         v/v2gAprYQwH8DF308vgetVNATLAi9Pr7rpa0W9MYPXGPbF/M+/gK8ykXigXAUnG9tQe
         MfaXCsCk24u+14kLCJQoJfuYQNZ/clLKKg5uRSnyLp+tN4jJUzZJnnf/p72GAMPnMuVX
         1ZncHU1VaZ9OATvOZLWBLBQb9eDCeT7I1Kan/LUa3P/LRTM1dagzAH3Mvg2GWEXsxOyy
         4JPGPkPmNECsj0WinhCpTl6gHudvraRs6CW9UctLoECUar6o6Uq3ENqxebV+xrewnlre
         aTAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qELc81M9;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id h10-20020a056512220a00b004d3d4e49b7dsi645583lfu.13.2023.01.19.12.10.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Jan 2023 12:10:29 -0800 (PST)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0F330B8272A;
	Thu, 19 Jan 2023 20:10:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CC8AFC433D2;
	Thu, 19 Jan 2023 20:10:24 +0000 (UTC)
From: SeongJae Park <sj@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH v3 2/6] exit: Put an upper limit on how often we can oops
Date: Thu, 19 Jan 2023 20:10:23 +0000
Message-Id: <20230119201023.4003-1-sj@kernel.org>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20221117234328.594699-2-keescook@chromium.org>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qELc81M9;       spf=pass
 (google.com: domain of sj@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

Hello,

On Thu, 17 Nov 2022 15:43:22 -0800 Kees Cook <keescook@chromium.org> wrote:

> From: Jann Horn <jannh@google.com>
> 
> Many Linux systems are configured to not panic on oops; but allowing an
> attacker to oops the system **really** often can make even bugs that look
> completely unexploitable exploitable (like NULL dereferences and such) if
> each crash elevates a refcount by one or a lock is taken in read mode, and
> this causes a counter to eventually overflow.
> 
> The most interesting counters for this are 32 bits wide (like open-coded
> refcounts that don't use refcount_t). (The ldsem reader count on 32-bit
> platforms is just 16 bits, but probably nobody cares about 32-bit platforms
> that much nowadays.)
> 
> So let's panic the system if the kernel is constantly oopsing.
> 
> The speed of oopsing 2^32 times probably depends on several factors, like
> how long the stack trace is and which unwinder you're using; an empirically
> important one is whether your console is showing a graphical environment or
> a text console that oopses will be printed to.
> In a quick single-threaded benchmark, it looks like oopsing in a vfork()
> child with a very short stack trace only takes ~510 microseconds per run
> when a graphical console is active; but switching to a text console that
> oopses are printed to slows it down around 87x, to ~45 milliseconds per
> run.
> (Adding more threads makes this faster, but the actual oops printing
> happens under &die_lock on x86, so you can maybe speed this up by a factor
> of around 2 and then any further improvement gets eaten up by lock
> contention.)
> 
> It looks like it would take around 8-12 days to overflow a 32-bit counter
> with repeated oopsing on a multi-core X86 system running a graphical
> environment; both me (in an X86 VM) and Seth (with a distro kernel on
> normal hardware in a standard configuration) got numbers in that ballpark.
> 
> 12 days aren't *that* short on a desktop system, and you'd likely need much
> longer on a typical server system (assuming that people don't run graphical
> desktop environments on their servers), and this is a *very* noisy and
> violent approach to exploiting the kernel; and it also seems to take orders
> of magnitude longer on some machines, probably because stuff like EFI
> pstore will slow it down a ton if that's active.

I found a blog article[1] recommending LTS kernels to backport this as below.

    While this patch is already upstream, it is important that distributed
    kernels also inherit this oops limit and backport it to LTS releases if we
    want to avoid treating such null-dereference bugs as full-fledged security
    issues in the future.

Do you have a plan to backport this into upstream LTS kernels?

[1] https://googleprojectzero.blogspot.com/2023/01/exploiting-null-dereferences-in-linux.html


Thanks,
SJ

> 
> Signed-off-by: Jann Horn <jannh@google.com>
> Link: https://lore.kernel.org/r/20221107201317.324457-1-jannh@google.com
> Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
> Signed-off-by: Kees Cook <keescook@chromium.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230119201023.4003-1-sj%40kernel.org.
