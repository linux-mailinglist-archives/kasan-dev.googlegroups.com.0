Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPW35H5AKGQEJAETZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AB87264CA1
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 20:17:36 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id k78sf2540479oib.5
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 11:17:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599761854; cv=pass;
        d=google.com; s=arc-20160816;
        b=zo9KJ+pDbs8u6y4pwMk45yDRX3siplUhoOmiFldkQWvuIG4GOihoR39twII4fF0HDj
         uoukl3vcpBXQGlBvIzUMxFgYpmWgg4V2E4QOn0c+kxNSTGK5BZt0OYulQxMM7e8OZtVW
         8ZK2MhK0dVu1okxaajyuPqy/VhLMLdCg37YecRLQpHbRrmgUkHESkXsoP5Dm+JgU8I6w
         OxNtlxwBKaJf30y7dIJyXph5/EiuhZAepJUXbb8U2c5fxac6AC6r9W8weiJyGB7PKqQy
         EcvyVFozYkIQUIP4SrMBgAXBgVvRb5AGeqAhL4Llh+0Ovdf1hQ4NioEveHCwuJt9ys6V
         uqHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=F0rNBmtBILCue03TolOLUo24IWL6W3JDhTLplcK4Mzg=;
        b=w44Je2QqoI6q+ycMykJ4pHq2n2dpE8p9LyfdcxMDzsCxRpCaJfG74GHVguT4tOqOww
         bhiOgc3acqpKBkJ4iBtrorwbHNQ3Vl+OC4t2dd3K/ox1fRBAnsKvtEYhGSRZfnl8JQg6
         jLSQJw0MbSlbT3yaAn+lrP1lSRu3rRptTtSc0hpYea64R/mbGSVp7tEZDMRzgyymC7rZ
         xGckO+o/VZsKnYseAs/v1/fX0F4QyNJibRL+NUhYg9r76J4WSWtDM+x8+S+x9cVVnPqp
         qntDPhEO02wLCkxVPNI6N29bFC0q7WjAqocT07/2K7rCOg27OJuTvSqP9BVhiESAnCTt
         pGLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QiJNnp9n;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F0rNBmtBILCue03TolOLUo24IWL6W3JDhTLplcK4Mzg=;
        b=kRCfmm1AwV6qC3mFVvVdzKUFNhUCKJrgdcJ5JayY4Tr0fq5yE6PtFSkLh0vew18dUA
         wvesoX+MzZE1ZZP28rDA35E1J8lCZZ3S5P9+SeKjz2PCWQdffsAPm6wb8u4wAW9zO0bc
         AoUOGeEg4szjvuZqREWjX5pDxxSuTCd61xt4k67wzu2UKKPviqqwFi8UaapqBXXAxe/T
         FQts3LlWqXf4FijDLWBttgbKnw+1pHvlguhW9lbIyI/fW8T/CRzf5OYaoPPM4tBf9BhP
         GwQ6eMeqtHhNW6gV+QLtW+9WtVTWd6BrI/vmDC23VVQNrVSRMfYBfdQGMQFnlTnfvxs1
         mJHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F0rNBmtBILCue03TolOLUo24IWL6W3JDhTLplcK4Mzg=;
        b=YJADzuXacrEEWHTv7U3TLBTBO/0FhutdD4jGWjCgebZP3m1pcve9E+fOBz4okURcaf
         hC/A+LZhcqVLbF/AgWjMcJJO3pfteIdFIaDqEDKSkvMvD6TTidPtilCrqBvZsG0CkDvw
         ICrBtqf+ulYFh5shKoPczrlAdLkwdHO5byGqVtfPyK+igIykoaub+518A3VMWSAAiN6M
         QSymdxPtG7QBeDvfo+gPDuWiz378rX1XmM9gqBEcxlsM3DH4QMmm/xJAcHITVaFhl5zo
         IbdEZP/9PHIA8thThVO+DWmmvLCNeoGqc7ve7YwjcsJ6BJNL5eTH/apPh3cGPFpVJBzB
         zKXA==
X-Gm-Message-State: AOAM531e0/X6JA6xr8r3/vgRmo/IEAZ7zExx90X1GzHqJC2irxi5JYzO
	1XEG4FIE3dlrEMfQ7ztr3Rw=
X-Google-Smtp-Source: ABdhPJw7A/VbRwGo5TWCB4J9l0X/4PD1Xe6EAqzdsvNhlLhfk0UuW8tedWNVLx0I4jDbP9DY6cO14Q==
X-Received: by 2002:a9d:4cd:: with SMTP id 71mr4951072otm.131.1599761854819;
        Thu, 10 Sep 2020 11:17:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4d2:: with SMTP id s18ls1652047otd.0.gmail; Thu, 10
 Sep 2020 11:17:34 -0700 (PDT)
X-Received: by 2002:a05:6830:22d7:: with SMTP id q23mr4801915otc.322.1599761854352;
        Thu, 10 Sep 2020 11:17:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599761854; cv=none;
        d=google.com; s=arc-20160816;
        b=d9BbT4iQj2qSJpIRErdYSRc+s3nyz+jJRSIjWJzOwcqT3Cz2/2qXnwIN0Y2RoQkd2D
         ZUC+ByD4iXvSm69IbBjboHPDE446AeDSxcfSUFLn4y5kZTYZPHHRTMq3aEOYkHEgd7v8
         WP6hAb4C9CRO4vQoOBvcPzrzNSpeDhSzTccFq7zz2j3fs1nKq8habVQKQchilu/nbOJP
         6+b+Z4wPUWBloPGies3w7qoFX2TOGSKAIkwvZj+xFqNzlZeP7qOZBNyE6RUvu8YKlLN2
         3HS3y3v+xsMAKR5TyfDFke1MjzWTLJTvcj0CdvPz899tFWxOz2gTTIu2NmnKprJT5ECP
         7KUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DtLKtH7cWRrM3fBgblOeHcZmUDs1Wpod83D+Qi8K1cc=;
        b=c3DCjLxtg4jA+D5875eWmoyezI7tmsHb4RnNdB8Yck/anhU3ezda2dVW+xLYW2TCX9
         tWF2UPXzsEWpuoB1t44l5qCnChBCclYPp0wkcDIBq5m7oB9NqTXoH5XytuZb8E2r8ZsT
         XpCoG1iTCb1X4mm8wzUJUXuKXmmwT2x3Ck/rAWcigSYYbr6RyXjvSaRcNuBAUbTfjnJq
         TZNk/5lr95k4Dkk87z2C1VQMDzwh+wS6/4JFcHPsCdIzwaYRrKrGAI+WDBVzvT3fd8WT
         xMYS1s4jWFeyB/bitdTFyOu6QrpKtfE7hj7gA0QT3ai04tFCCn//aVZUWXU27Hryxn6p
         3UVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QiJNnp9n;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id m3si496091otk.4.2020.09.10.11.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 11:17:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id o68so5233917pfg.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 11:17:34 -0700 (PDT)
X-Received: by 2002:a17:902:988f:: with SMTP id s15mr6555650plp.26.1599761853442;
 Thu, 10 Sep 2020 11:17:33 -0700 (PDT)
MIME-Version: 1.0
References: <20200910070331.3358048-1-davidgow@google.com>
In-Reply-To: <20200910070331.3358048-1-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 20:17:22 +0200
Message-ID: <CAAeHK+z1qMgg042rii5kNuDR1UeC9JzhXYMT=pSHnHQtoFFKew@mail.gmail.com>
Subject: Re: [PATCH v13 0/5] KASAN-KUnit Integration
To: Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, David Gow <davidgow@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QiJNnp9n;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Sep 10, 2020 at 9:03 AM David Gow <davidgow@google.com> wrote:
>
> This patchset contains everything needed to integrate KASAN and KUnit.
>
> KUnit will be able to:
> (1) Fail tests when an unexpected KASAN error occurs
> (2) Pass tests when an expected KASAN error occurs
>
> Convert KASAN tests to KUnit with the exception of copy_user_test
> because KUnit is unable to test those.
>
> Add documentation on how to run the KASAN tests with KUnit and what to
> expect when running these tests.
>
> The dependencies for this patchset are all present in 5.9-rc1+.

Hi Andrew,

Could you consider taking this for 5.10?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz1qMgg042rii5kNuDR1UeC9JzhXYMT%3DpSHnHQtoFFKew%40mail.gmail.com.
