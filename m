Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOEXQWBAMGQEBDBECMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FFD132DB88
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 22:06:01 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id i69sf14484525qke.19
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 13:06:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614891960; cv=pass;
        d=google.com; s=arc-20160816;
        b=ih+LnBXugNRsDo4U//bhByzVFLi5cKJKknz6uElzBowEhFbB34DXrCe38q9sQIbW+3
         CeOGWybnBkBUe6+oV1c/kpeko0komdYowy602du6tdIaz8B1rYtFYtn2uG//Zj/roSlr
         bCuxk2tVGYLD70HFJGaUB0v497XT61toassNToqWVLTYvL5CuzuGGEcyJA6r5+v11XIy
         dKPXuivE6EuKNQEh65AbE+VSQqTqQV4GRinKV6/rqEx4cxZKN/4LTixIIeSwlUhb6/7t
         SYm12oW4h2rBkER2hp/f5D/2QQYKdtERptqOM0ag6vLQa4aMIYagHdkZZ3J1iaZYmxpp
         rq5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VmaHRR/uK3lnl6sQQ8diIsQ41dnfStK0eKXv8HIu4ng=;
        b=0S/0qVDZ0ej1RRrzOuLc6mT7u/wf2HcUucq8taHqOLiq4aHLcFuJUD86uwMx6gl+nW
         irNwzoTQ8i7qpeltruiLI1PVve8lyQ8Fn7+6vLUwVk7VGU3xFpaFEwupZkHhc2AquLYG
         W9dMtysqXz9YB6m07tb6c7PuvkxPHX42UWc0WnujXrNc1iE7iLdQVKvlAvs38NJ5Igkt
         lyy6Gm6bWl6y6kbZRMifczbhJYT8m284pSP4ScRFTHvE+NDGYBATQGHMAmQQsspgL888
         0QECt9h+truzRql/+6za1pISV7ujbtibG8otQRxNRHcMH/ivpBUF13JafqJXq72FEx0Y
         doqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E1DX7PZs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VmaHRR/uK3lnl6sQQ8diIsQ41dnfStK0eKXv8HIu4ng=;
        b=H1y1pNn6KbvmTxz88UaszkLtXgMLqVnqpUgFwFN/tYKsSJYlWKUScN9mhcVyRBWO5c
         yjegx/9YF9aMtoV8cWn40Tm7Wfi/Ouzrcxh3NvLjPBEAghJcSVHHs7NdVVMI0GYdApB3
         CYQCiMXETrDF3TzckIGKQdCLKBLojyXlPg30C80KEeZUVZqot3+MXpC+qIowKCPZ++t4
         mw4mEiU3Zv4V0AUve9p5O+E/WwDa/jHLPYXAaQzAcXoFeGNqHNsvG8A8hQi1RPn8YDgk
         eBP7wXfOFAMAsyv5v8pN4pC5cSIO66GqrSpKKwXNY4s5VJ0PgVMBLnSFBkLxWB8i34C6
         V+YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VmaHRR/uK3lnl6sQQ8diIsQ41dnfStK0eKXv8HIu4ng=;
        b=jnig5Jgla3cmE0aQD1oItQQIR3b/hk9cZuGwReLt1eyn/UCJSo+/RI++NhaQVDe9xJ
         5YzoBtzmiDQUiFhPiQCcOHDIFqRRdEvxEe0kmlk6q56O3izpbTgYKTNwIv8wfNUSHH3U
         L4w9UaR+SxV1lHuEbhFrq42kkSr7x7yrvFYw4xMF4Nl8ClwFxz44DxQ12imqpyjnLwz0
         ane9C3pnyREB+cajaegnBV0zPpWPQj/hHycUZG1J36NgszmZSUfXtiodipnkZllpGXyJ
         isco0BaKQ0ID1/AuTajvQ0k3Km09y7rgtdWG8vw29x8jpBqXRqAPUCdFx8QhuXAewD2b
         BFXQ==
X-Gm-Message-State: AOAM533bGIG9CxR9LBUZGQswLf1HZhLqrbCrmYZk9nB8zGaUvVQ4MDQd
	XxT8q3QPbsCJx2QzbVDriv0=
X-Google-Smtp-Source: ABdhPJxeYFjqvY1ZJmU9BbWaAGQfleqLEvXhCX2weoA/HDoGa1lXaWBnj+A1jT0WpeExCLcEhR1xhQ==
X-Received: by 2002:aed:31a5:: with SMTP id 34mr5880628qth.307.1614891960630;
        Thu, 04 Mar 2021 13:06:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:7c5:: with SMTP id 5ls3757379qkb.8.gmail; Thu, 04
 Mar 2021 13:06:00 -0800 (PST)
X-Received: by 2002:a37:f50d:: with SMTP id l13mr5912688qkk.34.1614891960254;
        Thu, 04 Mar 2021 13:06:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614891960; cv=none;
        d=google.com; s=arc-20160816;
        b=B0s2/pO/+xLDZjBlGxdm0MQHy6vORw7UZxMbIahkSCZqbxG683UA14kvvGbRpNDo96
         Zk3Up3CS/+TrPc8msMA4UEl1TvcZ9QyMtV5xULQ5Co9OdqBieUIg9ujEbU1iBVhYrKno
         x8ZDJ4/wUe+v5wyHd+8yjm1Vd+zEdKA3RD2W0CgZs+J9NZrePtkLQMozNROKIa72rtRh
         MiDs+YuZ8BP1Q6BT8UYxobAufNx7LulXfM8NUCJi1hWWrbel0nip6sTVc7mRZbv5dcsb
         CYhkRkXkTR1UEqcxn8n8krCsnGsdBlov16rX0m9YcH8tt5/EISDFmMzflftZSDQKfkMm
         AQzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lgdkSDcMMDWh1SRt3hQoa5/TwUrpy7W6CPuK58HsLUg=;
        b=GhjXwo6mPKJBJLSFR6WkE1M3+u2Cvz97z2wiOVAAxpLRmCeGiMceFrztlhPZCeUTL0
         QJh7ZkinLUecWDaP3moXlMPghfNLkpfHb67Y993gt9Tu0UWF2N5Z2+PFfSirJQLV5SFV
         P19hFAUTE20M5fYfMEyDlntNw53pzqYVbZFV2CO5Isk5DR/88YEhdGy1a2pcHmp5AK0k
         Pj/BmvGxy6GLBUOXXSN+N3EnkkrlJVrHUQp1TNk1I7hAkkfIrasMvyrxP2QCzY1qQYvk
         wn0zkrClzb4Idd/EaaYErzifl4blolpQjpe0W/kegmLlwRApIzU/u1Al82muX6x/g+1B
         kjsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E1DX7PZs;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id b56si34402qtc.5.2021.03.04.13.06.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 13:06:00 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id a9so14829295qkn.13
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 13:06:00 -0800 (PST)
X-Received: by 2002:a05:620a:1353:: with SMTP id c19mr6192822qkl.392.1614891959772;
 Thu, 04 Mar 2021 13:05:59 -0800 (PST)
MIME-Version: 1.0
References: <20210304205256.2162309-1-elver@google.com>
In-Reply-To: <20210304205256.2162309-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 22:05:48 +0100
Message-ID: <CAG_fn=XVAFjgkFCj8kc6Bz4rvBwCeE4HUcJPBTWQcNjrBLaT=g@mail.gmail.com>
Subject: Re: [PATCH mm] kfence, slab: fix cache_alloc_debugcheck_after() for
 bulk allocations
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Dmitriy Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Jann Horn <jannh@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=E1DX7PZs;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Mar 4, 2021 at 9:53 PM Marco Elver <elver@google.com> wrote:
>
> cache_alloc_debugcheck_after() performs checks on an object, including
> adjusting the returned pointer. None of this should apply to KFENCE
> objects. While for non-bulk allocations, the checks are skipped when we
> allocate via KFENCE, for bulk allocations cache_alloc_debugcheck_after()
> is called via cache_alloc_debugcheck_after_bulk().

@Andrew, is this code used by anyone?
As far as I understand, it cannot be enabled by any config option, so
nobody really tests it.
If it is still needed, shall we promote #if DEBUGs in slab.c to a
separate config option, or maybe this code can be safely removed?


Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXVAFjgkFCj8kc6Bz4rvBwCeE4HUcJPBTWQcNjrBLaT%3Dg%40mail.gmail.com.
