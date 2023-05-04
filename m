Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBEFLZSRAMGQEWGU74CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 35DDD6F62D3
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 04:16:50 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-3ef33ed8843sf32719031cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 19:16:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683166609; cv=pass;
        d=google.com; s=arc-20160816;
        b=mVgd8wYqg8aeobmVFtsWMXM1OUq5kswZNfiyLdhxHep+SccWG50bDTG239TAMQjkwC
         nY4AEoRVmVXz/8I4T0bV45+Oxmm4EU6dIp7/6hoMg091vzBHWDDHxp8Ck0TcH6HENOIP
         LkR+4vs6oOZUOThtxX6VYGE9Mkt4pPJOWsXd34zx9stQqEhuwDqzmAXctXszTbRZQXGE
         CJjjGPzAxecOYnAOa9cmNv2GPqDagf8OYqLDBYor46cZAAGg5dF4lL3Of3y+lgn/hbW9
         Z0pfJLDRRr08jDqZX+OFYgMyoG7cLjxfydQvOpH62t/uH2LYikGxPnDrkDBbFT57+4VL
         QLNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gFVAhSHl4bDHh8ru9C02cx1uokFTxIsU8ZRRyQITjSQ=;
        b=vLmL2yC77E44dhU0YsMQ/5fdhMVrrRYutcVGObuiJ7xwOhha1odVSog5kLfaLQNLXU
         Ipo7tH3hUFcULJinOj/FFSMxhMerv/6+985vsk7y0BDI6P+regOOeaAXONC6OUYUw+A/
         M29kEeVXGpKJ/eJHsMCUTwgsmnuQazVC715ewnf3tM6/O1E2FYrsou/E0x+5ARr4DxTF
         092ti3GuHwLY5Zfl+XUhY48IYOtUhtF0iBIjUhIZx3yqWvvt7HnT2QffLguq9NMFH8l2
         3gcrOvXfMrE/ukvkaAs4I2ciug6JWFs69sZx7zMkWfz4fbxI0HMhY1rBbzvfHfLwvAZh
         2+mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=AVbZGT9K;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683166609; x=1685758609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gFVAhSHl4bDHh8ru9C02cx1uokFTxIsU8ZRRyQITjSQ=;
        b=pfKnsZ2QS2pez4tc+tPAkZOE036xY/7eucpHt0RUoImEPtKTHn7cpkOlB1DMaLwDXk
         te4gLyc6gGSgIXfUDpf8u2GorAWTLc5NZ69AYFzOctKqGbgPtEVgMPQelc0imxVooYTf
         0Ic/CwrNOLVJQow3kI0fcts3M04iaxWAJV9PDuO6Tfn7zUaYCaeFFQ1650wWIzMgtQkm
         m48YWCalgbx8dPYzNRUKJcj3hOiZuoY2Q372SO0UMs5VBrE96t2ZkwTfHFwaNIe07A9c
         HvpRRme4G/PBszNqkQQRyG9AZerCfCvlfINysSoJZZVFWv9/6Tj0aAu4TBYEb5m6hB9j
         uNug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683166609; x=1685758609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gFVAhSHl4bDHh8ru9C02cx1uokFTxIsU8ZRRyQITjSQ=;
        b=gm1WZyjpw7xLvFLgUSEf1EkBi2B15fGHe5a0FRy791VEdR72FK2g08EoIwALdleAhr
         vw/IUr5lFunZNOX/QV5a3xURJWtpsVAkSiqtfnplrCIFNUGh5CpoICmqLrIi/DjKfGmG
         A/aJItMEIHFibZHZpsl3M4hMwugpaa6ikF6XG8RRg+BObRn/xuKI/y0I3dJB3tVuv+RW
         pyE4vGtOnm7xoEmo6rPMBOfeZ3pgJqQa8i/AOrZ/DQlkNHufoOkEokeEL54mDp1BeMqf
         B1bXgpxGMI0znsyHNs4Duuki5Jg9VJYyWZ6NZaukomYjl59sI8cDVPvLAk+tq4uN/sMQ
         DAEQ==
X-Gm-Message-State: AC+VfDwCSjz8KqKM0Nr3tTT0RnRvbeqs3cn5ezFHbP4dIJbl9MLU7Gj5
	TpMgw/Ck904U5TPdHfWxPfk=
X-Google-Smtp-Source: ACHHUZ4Ql4ztxPqxKdpHZxig9tX+mK6wPejqLeiJ7gvA33Px+F+hAk5BB7vKEJfXR5z367i411SMaw==
X-Received: by 2002:a05:622a:1993:b0:3de:b5fa:dbad with SMTP id u19-20020a05622a199300b003deb5fadbadmr706309qtc.5.1683166608862;
        Wed, 03 May 2023 19:16:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6f09:0:b0:3ef:3784:2c24 with SMTP id bs9-20020ac86f09000000b003ef37842c24ls16610271qtb.2.-pod-prod-gmail;
 Wed, 03 May 2023 19:16:48 -0700 (PDT)
X-Received: by 2002:ac8:5a4f:0:b0:3ef:499a:dd99 with SMTP id o15-20020ac85a4f000000b003ef499add99mr3034951qta.66.1683166608219;
        Wed, 03 May 2023 19:16:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683166608; cv=none;
        d=google.com; s=arc-20160816;
        b=Pln9qHR4Cv2G1/7EwKaou9Kh+XaXlrAXGNDTRPkAhfXzxJJogfuK6MC2P6xKN69G8d
         sXxh9BXo/kqmyONsG9vd3UXjEFhquw8+u7jttBGgg+3eWsCVt04MaMlk3jEu3WKRqmHl
         RkdCEDL4TziR1Reze9wbF8Plltx7YGMufO7dhieGLwSo81ahC4otl0UkJL00vfYNkooZ
         oAX//H15pUoGe8BL5x9fjq8lLTaG/7cH4MkumJUTGBKHPcxmeP12OkNWOUTwyiigmf+b
         z30OMPyNg/t+0VvHbnxpqx/aMZ7u+ur1BFBXnjGfzK2N6fZswPrMakzmZH4Z1VtyHGf5
         U4ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=xki9EImbF8EHplkOG7u13eoQc3pPoVT6i0i48IKNO48=;
        b=PUobwiNY+wDWTxmRzWZqoskM474uchmvoD+8JM04NJX2mkEZKa4JnKpNYIn/pPcZba
         hMacr3Y21rV2EEGpcXzSRn5Cz7z3+FPE3YzveoMdMQ8wKh3mPlmkY2iG0cTofH+aAxzb
         LjOMKLrIk6ypsMHrapmJ3TBqbyKl7xTp64FZWB6r0tUQnlgtYs9NxNHkCQ/CE06PgeZq
         5Le5JQLd9gVlGfChYypUuuinaw/F16kHmNAvoIedoH+hW3aYUZQaLlZZooonYnOVVYiW
         QBOmEAVDnWNgPemkDvLCflnfiiqGuKjRv65VYVyz+NJp4UlBABmKEPBHdLCkspuupVXr
         IizA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=AVbZGT9K;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id i16-20020a05620a405000b0074e4cf13d2dsi1476084qko.0.2023.05.03.19.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 19:16:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-517c01edaaaso3981079a12.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 19:16:48 -0700 (PDT)
X-Received: by 2002:a17:902:a60e:b0:1a9:2b7f:a594 with SMTP id u14-20020a170902a60e00b001a92b7fa594mr1984126plq.29.1683166606837;
        Wed, 03 May 2023 19:16:46 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id jd20-20020a170903261400b001a682a195basm3871260plb.28.2023.05.03.19.16.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 19:16:46 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 16:16:44 -1000
From: Tejun Heo <tj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFMVjAze4tu0DUXs@slm.duckdns.org>
References: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org>
 <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
 <CAJuCfpG4TmRpT5iU7bJmKcjW2Tghstdo1b=qEG=tDsmtJQYuWA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpG4TmRpT5iU7bJmKcjW2Tghstdo1b=qEG=tDsmtJQYuWA@mail.gmail.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=AVbZGT9K;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 03, 2023 at 01:08:40PM -0700, Suren Baghdasaryan wrote:
> > Yeah, I was wondering whether it'd be useful to have that configurable so
> > that it'd be possible for a user to say "I'm okay with the cost, please
> > track more context per allocation".
> 
> I assume by "more context per allocation" you mean for a specific
> allocation, not for all allocations.
> So, in a sense you are asking if the context capture feature can be
> dropped from this series and implemented using some other means. Is
> that right?

Oh, no, what I meant was whether it'd make sense to allow enable richer
tracking (e.g. record deeper into callstack) for all allocations. For
targeted tracking, it seems that the kernel already has everything needed.
But this is more of an idle thought and the immediate caller tracking is
already a big improvement in terms of visibility, so no need to be hung up
on this part of discussion at all.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFMVjAze4tu0DUXs%40slm.duckdns.org.
