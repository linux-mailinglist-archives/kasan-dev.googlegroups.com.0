Return-Path: <kasan-dev+bncBDTMJ55N44FBBOPTYSWQMGQERCMFL6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA21A83AE48
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 17:24:27 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-50e7ddf4dacsf4536683e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 08:24:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706113467; cv=pass;
        d=google.com; s=arc-20160816;
        b=kTaCMRzd5N8mBHCkPvmPaJZwN+Z0hPZX6pAmq+LLJ4Y9JX+KFFdDKyHgpRwDmAqtZY
         ubuIJ3FxuXl+p2OcaXAE7+fRzQfxhKluyxh5UZEi7l4306CEvHf+aDY16MF5E9dtS7Kb
         1p6DF5M6RdHWP5COzsKQAPDfJujDfdzMdGR3AQecq4JdViPOouzpqi2AKnEcPiYP2ZcI
         Kk+alGlGvKPSU9GnS+axKbBZwXe8IktC53Lc3CDGJdE5Ks1R2T0boA8XUHb/HbDCKjRu
         TJPkkdhBBPUmbX3tqEXpUd583TReMeUaEHr3Ldgf8fgOYw1fbIXYSNXOtKYF6X9T2xll
         U6uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZwnZbyfvRwcXmhDNqbqR4bAbEYknv42eK0se/kXA8JQ=;
        fh=4YVsvSw89YLB8BwEpRY3CJXgqRUaRqMGbbw+saURfhY=;
        b=XdUKv1txnuj+qNYy4JNqj/kZSpD5enfjaKj1vc3nXyNWWYyOco2FDz4PJ4+WUXGRpu
         uqbaodd0bPDCpanAHSE5wwSqenr0wLHdebJS6tcEAttfTlRkfym7Et2zYx4G8uCSfMgS
         3TEuYCoXSslvutoGIKhzICXT+AWYuMx9A2z4xz+TFnxb22rf0NDepKVbEU5uNpvtfZdS
         XFOkiedRFh05h4SRRA5DbOOn2xdbD0FaN7KoJasns8fg+p6pFQQ6SbbEXdRErpNaFnRe
         m+bPdJzyFymS0gi9nqeuF3yIsr38GKbfmMaz2WtV+pKfkDPdTR8omPqlHngcPH+WzJqF
         nYUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.167.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706113467; x=1706718267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZwnZbyfvRwcXmhDNqbqR4bAbEYknv42eK0se/kXA8JQ=;
        b=NB9liGNloaKdQS04g0rMKqMqQTuz/FBhWRX1SfCtQ4u2L1eNPSyL5JuXIqcqO8pELs
         VeW8uJ+LYrbaz4AfJNMfqclpUI68k+cVzImvF+Iiy7rO2HbkpQRAcGX+/fnf0KNUyvQ1
         /bPzTIYwly7exJkB0e9P6tILb+0Qmt99ExoMYy8ruz1kKuCFY9/KgEagG06FIkAh+VzF
         sSo+d2QPJjfCav4URvjMus4qZKna6dJLrkjXf8MTpuewuYOxt+Cj2mnHUXa8TDSNXJQ6
         H8zBuCcqTekoMdKAGHUkwLX0mV07PVsMH92OEZEggHVuFYv1LQOO989BQD3g0oAb+Dyr
         q23g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706113467; x=1706718267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZwnZbyfvRwcXmhDNqbqR4bAbEYknv42eK0se/kXA8JQ=;
        b=YADRSaYyCQKdaAkro2bYUMn5hgchyiS+0mOQMjbTwjdhfhDEYfZHfaLVGXLMOOQrjj
         LJZgsrD1Qe1B2ovn3vpgepxjL1zwOPOfv2255vR0THXkLUsDt/I40kcVpxVZAnbGwVBm
         6fDhwLa7WMgP03MkFLdb87K90Vhfh7yuhfveP1Aea84lvr+ImExCBSQcrLJLKIv9+k+t
         IjpS85bKdXpBixe6suEAMNOaECYeUO6NU2WURC4qvvSJjCap/yfWRaTcp8nkTYQybK9i
         r1lte3aH8yv53R2XRfckhe1mP7Yivbg+pAbxQEQnh+DMQ0CFOY2W8s5XiMNAMsyFkTnY
         1bOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxDg/a+8jy4CTfBjjRI9U4NhckeIworD/5z4WVHqcLOE9os6RtY
	JcNpuAaABwUh/V+aDzQokd/LDYVB7KvaCidnP6zPJNidAb1GwIOf
X-Google-Smtp-Source: AGHT+IG+f7ridaDMSAoapFRvFyxEy1pSWGZkaKmAbqeAJZVibeXQ62d3ofngfPdAWQiWa6ngU+qhhA==
X-Received: by 2002:a05:6512:3b8f:b0:50e:7c9b:a8b7 with SMTP id g15-20020a0565123b8f00b0050e7c9ba8b7mr4318118lfv.99.1706113465904;
        Wed, 24 Jan 2024 08:24:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3451:b0:50e:7aee:6a37 with SMTP id
 j17-20020a056512345100b0050e7aee6a37ls133104lfr.0.-pod-prod-03-eu; Wed, 24
 Jan 2024 08:24:23 -0800 (PST)
X-Received: by 2002:ac2:5193:0:b0:510:156d:840d with SMTP id u19-20020ac25193000000b00510156d840dmr358050lfi.29.1706113463479;
        Wed, 24 Jan 2024 08:24:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706113463; cv=none;
        d=google.com; s=arc-20160816;
        b=ZmRvR5aVnCZEbSeikOERiya+v6rBHKHj7KgD7iRp8f9SJ4rViHA0Gz5Qm4xE3aKsgA
         yKj6ruLLaRLXTgmqofMPqDxRR0RapSG/EZvPXhtXxth6e51trghgzmlbl9YV7AOZkkME
         stTh9GgsMVnV35VSg6Rju7aSxQlnhLmA9O9maGfz/goHmUeIhyU6zgYF8cAREj8ks6q+
         Ma+BVxR/NXStqAjSokmlZBj8xXzNusDWkH9ZYQv7uXdnaLgydEsALfY6DGWn9R+xfoAN
         a0sDLe7WiricKUiKbx0CRKaxPpztSmlfc9q8xplXjNryc7l12SI+cd9oKfpeJlSAFZil
         ktyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=eMrT5P2w10tw7eLH7q5F2CQ18PCwIDF5TrbVadGlCl4=;
        fh=4YVsvSw89YLB8BwEpRY3CJXgqRUaRqMGbbw+saURfhY=;
        b=siu0Yd8zsxEsd7wO6V2CoN4jGxRA3c1XdyTEryqDdQ0T1nW6ONJjGgz9l56YKPL0ZL
         sYEYGRUpHbPocXvVen2d6yoOhfAw6JXjFfdv0o6Wi8jxL6CIbDzNn4HJry6PH/z1PcZF
         u3Io/CJLE4kL8nw5QviLBHH/aStN4labliRXUH2dzHU2yXR2CPHYay6f60BCxgCVRbrw
         Qx5YknwR/G3S54lJ/sSgaR0+f89m5eh46vsEb00q+qTmKL7LSzJo8v7gZh39pqaL4COt
         eO/oDHrellAsGGu6BD215BxUWJPwNrbeB8a8QD7wIhfQAbJHFP4E6HAPm07pG/sxUXGw
         DJLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.167.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-lf1-f52.google.com (mail-lf1-f52.google.com. [209.85.167.52])
        by gmr-mx.google.com with ESMTPS id i18-20020a056512341200b005101461d028si51336lfr.7.2024.01.24.08.24.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jan 2024 08:24:23 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.167.52 as permitted sender) client-ip=209.85.167.52;
Received: by mail-lf1-f52.google.com with SMTP id 2adb3069b0e04-5100ed2b33dso1608297e87.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Jan 2024 08:24:23 -0800 (PST)
X-Received: by 2002:a19:ee10:0:b0:510:17b6:69e with SMTP id g16-20020a19ee10000000b0051017b6069emr68370lfb.89.1706113462769;
        Wed, 24 Jan 2024 08:24:22 -0800 (PST)
Received: from gmail.com (fwdproxy-cln-011.fbsv.net. [2a03:2880:31ff:b::face:b00c])
        by smtp.gmail.com with ESMTPSA id wh11-20020a1709078f8b00b00a26f6b8be1csm47026ejc.75.2024.01.24.08.24.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jan 2024 08:24:22 -0800 (PST)
Date: Wed, 24 Jan 2024 08:24:20 -0800
From: Breno Leitao <leitao@debian.org>
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Message-ID: <ZbE5tBBjlhz3JN5+@gmail.com>
References: <cover.1700502145.git.andreyknvl@google.com>
 <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZbEbmyszaK9tYobe@gmail.com>
 <CANpmjNNnrKYKkV74rcBUkpA09KqwHOjse9J9aCHPRFuYKCQM2w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNnrKYKkV74rcBUkpA09KqwHOjse9J9aCHPRFuYKCQM2w@mail.gmail.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.167.52 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

On Wed, Jan 24, 2024 at 03:21:26PM +0100, Marco Elver wrote:
> On Wed, 24 Jan 2024 at 15:16, Breno Leitao <leitao@debian.org> wrote:
> >
> > Hello Andrey,
> >
> > On Mon, Nov 20, 2023 at 06:47:10PM +0100, andrey.konovalov@linux.dev wrote:
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Currently, stack depot uses the following locking scheme:
> > >
> > > 1. Lock-free accesses when looking up a stack record, which allows to
> > >    have multiple users to look up records in parallel;
> > > 2. Spinlock for protecting the stack depot pools and the hash table
> > >    when adding a new record.
> > >
> > > For implementing the eviction of stack traces from stack depot, the
> > > lock-free approach is not going to work anymore, as we will need to be
> > > able to also remove records from the hash table.
> > >
> > > Convert the spinlock into a read/write lock, and drop the atomic accesses,
> > > as they are no longer required.
> > >
> > > Looking up stack traces is now protected by the read lock and adding new
> > > records - by the write lock. One of the following patches will add a new
> > > function for evicting stack records, which will be protected by the write
> > > lock as well.
> > >
> > > With this change, multiple users can still look up records in parallel.
> > >
> > > This is preparatory patch for implementing the eviction of stack records
> > > from the stack depot.
> >
> > I am testing quite recent "debug" kernel (with KASAN, Lockdep, etc
> > enabled). This kernel is based on
> > 9f8413c4a66f2fb776d3dc3c9ed20bf435eb305e, and I found the following
> 
> This version predates this series, as far as I can tell. Can you try linux-next?

That is true. I will retest and let you know if it is still
reproducible.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZbE5tBBjlhz3JN5%2B%40gmail.com.
