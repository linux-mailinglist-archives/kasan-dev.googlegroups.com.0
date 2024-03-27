Return-Path: <kasan-dev+bncBC7OD3FKWUERB5G5R2YAMGQENH2NGRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 68AA788D5DB
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 06:30:30 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-368a444b5dfsf212465ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 22:30:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711517429; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fa/+KrzATE4hoG4IRAPUP3BE8ZuTYoXpfz5iqlVNJzoiPT6lNo9yYzygh8xTPS7Gpt
         aUtzFh2rU+Ef4TcJZh6JsswuVYM+JZee7F9utlr/2WERHwouF+ZorlyIp3SiSEha+Toc
         FmX3EQGSpaBwzKA8QtYcwgDtdiHTGBcS1KTPvYGqIPkk7kV2fhOPVjYBMtbNC9VLWkw8
         j/JIPNK5qUEcMJ0YlafflypsUWxaM9BX1vCnk5AtVJuSMa0Pny7+x20d/bSd4aI9aFFi
         GglpMzS95V97Qqekt6hlhNQWA4i64MwgNq/hqIOVNsRhy9aO4TozyvCH5d79lZ+A2oA1
         ekWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LhFXF8Jp4Nq3NX7jUA0Q7zTnRYqHL8nIXaJgCrZg3aU=;
        fh=qhJL1MXNBunAVkYEUAn2RQmfDYdKHV8D2FRTKdub8C8=;
        b=qlWshvJ+r6u6+CU77vmW1zDkI1Dm2rT5MHQeRkPvZRS02ynRhJZ1ZyPZdBY+ETMFwJ
         JHJm4Ey8C3I7w9ZwS0M/IescTffilVaIupVrlpSH2vF1D7CytCmDMwFj6sIwl0pjwaEk
         W10Vfha2HKUKn/c0YE4a5nWkBid5s7DcZIAgl5sbRwQfc6lWf2PvMN2MBZp91+lS32bc
         A3Ha/liOYzzgoLfnG/NpHng/lzggbhbDGcia/DeKuwTUpcSNfG/PprHTbfq+pqCPjj1r
         O4efDjsCK95twF0obel1QV3dng/7TrViRcgnATWPq5N8X7uzQyfs6HFE47olvgXzauIh
         O2MA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2AvSvtJQ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711517429; x=1712122229; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LhFXF8Jp4Nq3NX7jUA0Q7zTnRYqHL8nIXaJgCrZg3aU=;
        b=KkvNStfzkZ38h2oWcTtfDnRh7P3nDTbz4mRqxDqFibTzZ2/uBOJAE1sYMDITJFFQ+B
         osgZlB4VpdB9ZTV/RW//awdl7bLvAJfzfWbAi33QkWBIhyq86lt/tKO9a5LXyCpcPA8i
         0iWHvluuV//7Zy/b5P0FrVNx0fYuTAhATp/HeFHbTK6BW5dXQqLeQNbz58dWai2eN82E
         A+FrTWo3H1wkMKJ2lXDw53PckJq3QG7ohe0CboiCBQYZFSDkMVZht64Qi73Z1sEhFv9p
         fiQZ/YIRXkH5XlSR4C8LBCYrVBbchAMpNpZ0DmEZ53LGpbUOvrcUa4iL3gXLY1VOMgpQ
         IxHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711517429; x=1712122229;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LhFXF8Jp4Nq3NX7jUA0Q7zTnRYqHL8nIXaJgCrZg3aU=;
        b=B0nxPmKWsUgHzIMCNgY/Ii83fZsfK2aEO5f2S53DeNTkuW5nItW4KkOphhlzFYnozO
         yVKBJb+bjhq7EYABCahDy8wr1SPEXeakOk5I7HmTRJ6v7pRtT6ljLWmVdeY9vzzrVcMM
         Hd6X/1n2jMbLFQe2oH0zcQE09kW1CDKWcDmHNx0kYo3Zd3qBQjUHd+7Ul6QHPDSCb08C
         VSn+06hfys0nq9x+zAIyykfkQQqJuwqOMQA4CsRGDDhlsQodkr+yZjnTwyK74CWef5r0
         kjFWsQpm658kJQ13ZE0DEVF2YkIO/YStXzCea2RYb1NpEAwpFKcTd3/l1FKsp+Jp5QEd
         QBhw==
X-Forwarded-Encrypted: i=2; AJvYcCURT3aFjscz8QAz9efTOEBKswWWr0AzyOdAb4eWslYounXhwT11FdskgESDj1zt0qh57jQjehy9eLJ9tynrj5M9HAm/X2Vl8Q==
X-Gm-Message-State: AOJu0YwD+0IVzpoZQa8WJVaLueAYHsTvjV+nEhiw0ykswMK5OU4SXi+e
	Mq0WsP0LJ8l3XJR99Z+ZwYocoaHLNo8Zjo4nCkqcFTnqSEI/n7F3
X-Google-Smtp-Source: AGHT+IE6ThqoVbrqSto8w7IPnFdbi1MM9vUl4aNOQw3ACo/E8aPms3cMa8Wt2isqDrxSPAbHVTVf8A==
X-Received: by 2002:a05:6e02:12e1:b0:368:b471:5ab0 with SMTP id l1-20020a056e0212e100b00368b4715ab0mr553iln.3.1711517428740;
        Tue, 26 Mar 2024 22:30:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dfc4:0:b0:dcc:4b24:c0dd with SMTP id w187-20020a25dfc4000000b00dcc4b24c0ddls5051810ybg.0.-pod-prod-08-us;
 Tue, 26 Mar 2024 22:30:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIHQVwvLMhUllkQtVyFYhMj0f/5C7WHFX54QMqBcjWRmRVThfSwe96MVYueJiiGuOKsHnJLI+qEVOg+JTccFZUPQrQxY2vwm9o/A==
X-Received: by 2002:a25:b1a4:0:b0:dcf:9019:a2fe with SMTP id h36-20020a25b1a4000000b00dcf9019a2femr71651ybj.64.1711517427768;
        Tue, 26 Mar 2024 22:30:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711517427; cv=none;
        d=google.com; s=arc-20160816;
        b=vfsnOQ7bpRj7qmmwpKfefeGORkgqWXegWhpuEb76qyzjJn+iBVSK6U1yERjmqvFt2E
         1wJgxReVzN8RInILhn43IOn+wVkMd76nke40lFm9xrpQb1ZUXOtBek49jlOGIxXdSGkv
         AXPowcusVNyrYgpQzVQ81ktg0f9wikd3iU388Ej3CBFIcWAOlIt34Wdp7IytU+v8xVhz
         qNnl2oBYdnVvqhTAGUi39QCAE6JUbanMCMELHQXQ85iD4jj+8WDT/JKmBP/ZwCluPAxs
         Jkdyb+6OAvSo3WXs5vhHn4RY1eOlL6xseyoWND8YmBKbWLTlx70xBBSpDnNsQLrSmfwr
         cgYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=46OYyrCzIWWF/3s+Ae2ZfY3Ah+E/dlrHPDoFMxmXEao=;
        fh=LXyOyy2bqfGnaPx6mTAFd5E6CZH8Yf2psugqTwkuBnw=;
        b=Ywi4Sy6nvsc2/qZc5kk7Y82HSXQB6UZKej/mhw1nBw7d6P28iN8tmQd5D/pvz0S2fN
         jwFlJkeGeqMjEm0vx3mgl59EB75lrOWsFH/61LM5Nd5pM+JQ0F1BXrJLplRaNs2GwPnu
         3bVid8nRlfx3j15C/x5FVTs/7s/hUFVL5HdnC7LaWViAH9MQxHI9iY2UmdyNAhmdQ9em
         3F5ECf0q5l6pnu4p3Ou4JhqkQS2+gQhoea7CrXrwXFxeBfuYF1dpEQf/JeLSIQaqG10+
         jq8fWu7x9ST/zucIONOCO0RaOuKOU0KugVie1Q/+r5zoIKqz7uMsY2lvfJhZysslRCbs
         +LOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2AvSvtJQ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id m71-20020a25264a000000b00dcd2dd6bba7si827986ybm.1.2024.03.26.22.30.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 22:30:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 3f1490d57ef6-dc74e33fe1bso6116148276.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 22:30:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVD5DY5AdFQolVHVlPOqKQpgYRt0c/6TQOoO2eT8bN4KFIMe3g7ypBDNzMZgQNfQd479enYr72ERfyrY8PqnanQl0XndkR3BXA5uA==
X-Received: by 2002:a25:db42:0:b0:dc6:be64:cfd1 with SMTP id
 g63-20020a25db42000000b00dc6be64cfd1mr104510ybf.36.1711517426957; Tue, 26 Mar
 2024 22:30:26 -0700 (PDT)
MIME-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com> <20240321163705.3067592-15-surenb@google.com>
 <ZgI9Iejn6DanJZ-9@casper.infradead.org> <CAJuCfpGvviA5H1Em=ymd8Yqz_UoBVGFOst_wbaA6AwGkvffPHg@mail.gmail.com>
 <ZgORbAY5F0MWgX5K@casper.infradead.org>
In-Reply-To: <ZgORbAY5F0MWgX5K@casper.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Mar 2024 22:30:14 -0700
Message-ID: <CAJuCfpFaiQjOr5jWiNbz_B3ycrgNTfw+Vbpyk9EHqvek4bDPsA@mail.gmail.com>
Subject: Re: [PATCH v6 14/37] lib: introduce support for page allocation tagging
To: Matthew Wilcox <willy@infradead.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2AvSvtJQ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Mar 26, 2024 at 8:24=E2=80=AFPM Matthew Wilcox <willy@infradead.org=
> wrote:
>
> On Mon, Mar 25, 2024 at 11:23:25PM -0700, Suren Baghdasaryan wrote:
> > Ah, good eye! We probably didn't include page_ext.h before and then
> > when we did I missed removing these declarations. I'll post a fixup.
> > Thanks!
>
> Andrew's taken a patch from me to remove these two declarations as
> part of marking them const.  No patch needed from you, just needed to
> check there was no reason to have them.

Sweet! Thank you, Matthew!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFaiQjOr5jWiNbz_B3ycrgNTfw%2BVbpyk9EHqvek4bDPsA%40mail.gmai=
l.com.
