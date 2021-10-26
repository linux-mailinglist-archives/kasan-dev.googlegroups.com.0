Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FA4CFQMGQEIAHH42Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id BB48743B400
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 16:28:09 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id nv1-20020a17090b1b4100b001a04861d474sf1393065pjb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 07:28:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635258488; cv=pass;
        d=google.com; s=arc-20160816;
        b=K4Z3wxpWj10ZTNgUYKsneyA4/wXHkhU9eELC9I8JbfeQx1FCE5PCo/kh022pmQhR/j
         nEdbfIxXYl46S5T9uCdRHkPz1QD/vtRJalaCazrl4VnYO2FF3zdusS/VBionL4tV+tV/
         NHgLvFTbUF8Tj9vbfawNNltnxfYGTnPT5t+5upIEypoTIbgXecz5m38Nu02FgCH9aA9X
         2+EtfC6i698W917vTZUiNH789Cjclhne4JYyBi4NueWYBn9hPeEU5JRu77gH5QNj3i8o
         FAK6lVCZlo5l+xZEFiUE/7NGqdZiTo85UAsyNJq5teuLRUVkLQnWjPbzSiloEKjQOcUO
         KpBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=i9T0gWEUcnfQlDf3FJf7ZICWhli04XfsjezkeFuyPLQ=;
        b=TjgXwGTPXsmlGzGdW8UqoYRYa6dEaIp3OiXt/FSmue57daUeuBKtEzvV5sfxHrGCz/
         IlyX6JOX1w/jflzfuhUQY3+CGZH4mXxxUtNpzjLLCzQLUevJPapjfipHBCtzyL2HHPoh
         VD1qbZw2riYvBslAZj6uVlE0qlvj3Nr0w6gZs1aDoGmp6XyEvLw82sGXRopM9z6TG1Og
         nn+KYDhw6/WnsE3/YIs9ChWGFP6y+lDeHqFKIu2tsYH9PxaGlryfbTpo/vQiPI/lYIm9
         l6ErDhUNzkWqDUyiiTcdMk/aU453eUFEpWw2fP2Gd6dFY7FxZ1ynQqTsZ6ksz18vihtH
         KOmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VYO509It;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i9T0gWEUcnfQlDf3FJf7ZICWhli04XfsjezkeFuyPLQ=;
        b=eA9LS5Zco+bYEX9BzSXV9gyYFTpyKucfnzKMPN1XuyN6r/10brVdUC8T/5gg+fOdX5
         nCevDJDpdDWWEs1qlwKFEU3ZB3F/NmYXjXblQy6AZ3Bw4K3okug8isdcXIrKdA5+spiZ
         TGbzmavZeoOK+OP6gI2Xs+MElJaYtfeloHGRTY0mIJZBEGRLTZhTDpMM2AEdcF3ku+Bn
         JDgZ9jMp13Y1mplL/clmD0+YTBGBBYJAQ4E/pmKN5JtH2sy8s826kwHZ6XgsYqKiN4wL
         YXcWjO34bkizDfrIxbXQkd5lOtBSCwu8okAxpVP7q/TBtgJNZujr9BZoEiVHtKcEH50h
         DZlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i9T0gWEUcnfQlDf3FJf7ZICWhli04XfsjezkeFuyPLQ=;
        b=TDvOxgXiAQ+rYYPPW9noMGEBprYAR3Pc4mLSYuFTymsJeeYgcmaElWPz00HVCmM981
         DpOTkyjSgbqbo9nIe0YN4I5ys692+AbOIcKz0tlh4tXe0K8k6tVODoGyuTq0QLutcMqq
         IHT5ZJWfMgvUvE5v1l4vgJhIPNjSU4LOQlqUgBexBsIsNbHm9UtwHBdmTpZL6Jn0VtnN
         PGDkhcMyJ+/lTaRtJ2YhIKqwfDywdAmsZOf1ET7SyhzPLMXDE9KvSqntjnzLZwpEe0fY
         oxWPpIR4pafjp5MWxs395ayUUURy1v0ExcvD5/AJ6wfr0SMdeGCpaEua4bVKJIOQHe6U
         vE8A==
X-Gm-Message-State: AOAM531dDhjX6qFSmSFS39VCcBxDBiBLln+L0eIdcBd8TpAkk1nwF4nI
	uvv3WOhroTiWP6QuXwP9oME=
X-Google-Smtp-Source: ABdhPJxCXtKzcwOmL3461A7Hc3iw40Oypk8R4wPic2s9NtvQR6xmWMJv+Eh5/6Ec5p4axjPHDcd7+w==
X-Received: by 2002:a17:90b:3a81:: with SMTP id om1mr44130289pjb.184.1635258488476;
        Tue, 26 Oct 2021 07:28:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec91:: with SMTP id x17ls251289plg.5.gmail; Tue, 26
 Oct 2021 07:28:07 -0700 (PDT)
X-Received: by 2002:a17:902:6b0c:b0:13f:aaf4:3df3 with SMTP id o12-20020a1709026b0c00b0013faaf43df3mr23195671plk.75.1635258487865;
        Tue, 26 Oct 2021 07:28:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635258487; cv=none;
        d=google.com; s=arc-20160816;
        b=q9/Y9I2WcGo+nBaYz9bpdHZMzCHp554QRg5MghMwulTMJJsr1IYK+TyyAg/puWF76Y
         aDtIibKkSnca4n1+h5BkqTiiw/mIXOwSwVl2iW/w65wF4xja7mDH8YTeniLik23kczlh
         4OwlXLGETsBEAHw9KcegJrlodvlnVUY5A5dxaJw2ssz5zwMw4fsYqZFF/ZMYDDJTeK8r
         vUUqCQEuGldFGgZeLN4Hun5g1jvf+tpR/6S8X7oYuNwLwktcojQnZ7eOba1XlqL7q4zS
         6MO/qzoCq1v80X6U71j2m3puOg1EfPCilqCxYt4Cz1keWulktXdB2ias7biuL4vNLLl5
         HYQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XSp/cI8B6tGIWQYSUxjLhFFTXMn9RrA+lvWtIcl5Xxo=;
        b=c8xQmxu13a2c+wbYjqAV3AhjHN6csH0btMNNbuauXk2qkuZLgu9wHZT3U1GN1ItuF5
         4S8qw8Cz2Xvqx1uaiL6pzTWLO/6oHUl8eHTCbbPxAlurKOZt7cUi5LhqXZJHEPtoxmIq
         80IOievkzIXCpM2T+vkMtUPRnBKgdgEWsDXZ6/jmkg1uQt+TJ9KuciuKmUPTMkYZ8KgA
         zy4P4ccLCVIkqKzoGd0PhNX1Qj7PzP9x461TM5ysbRMhBi39btfNCKIIrQwYQdpbySLq
         1KB9dOclgyOHrmPrCeYfJkRk04yGBQl9DGy9zoVP14pp2/E5udegq1P/Km7j5hMbTH6H
         QicA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VYO509It;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2d.google.com (mail-oo1-xc2d.google.com. [2607:f8b0:4864:20::c2d])
        by gmr-mx.google.com with ESMTPS id w9si1420055plq.0.2021.10.26.07.28.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Oct 2021 07:28:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as permitted sender) client-ip=2607:f8b0:4864:20::c2d;
Received: by mail-oo1-xc2d.google.com with SMTP id k11-20020a4aa5cb000000b002b73749f3cdso4892685oom.4
        for <kasan-dev@googlegroups.com>; Tue, 26 Oct 2021 07:28:07 -0700 (PDT)
X-Received: by 2002:a4a:ae0b:: with SMTP id z11mr17001006oom.25.1635258487022;
 Tue, 26 Oct 2021 07:28:07 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000009e7f6405c60dbe3b@google.com> <0000000000003548bc05cf4202f3@google.com>
In-Reply-To: <0000000000003548bc05cf4202f3@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Oct 2021 16:27:55 +0200
Message-ID: <CANpmjNP+MhERRyixhHo55Fr99G0OggGwS6-KiUFx_99earQhqA@mail.gmail.com>
Subject: Re: [syzbot] upstream test error: BUG: sleeping function called from
 invalid context in stack_depot_save
To: syzbot <syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org, dan.carpenter@oracle.com, 
	desmondcheongzx@gmail.com, dvyukov@google.com, hdanton@sina.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mgorman@techsingularity.net, syzkaller-bugs@googlegroups.com, 
	tonymarislogistics@yandex.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VYO509It;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

#syz fix: mm/page_alloc: avoid page allocator recursion with pagesets.lock held

On Tue, 26 Oct 2021 at 16:08, syzbot
<syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com> wrote:
>
> This bug is marked as fixed by commit:
> 187ad460b841 ("mm/page_alloc: avoid page allocator recursion with pagesets.lock held")

Looks like Dan's "#syz fix" made syzbot think that the title is the above.

The reason that the commit title only is preferred is that commits in
trees like -mm don't have stable hashes. Maybe if the hash is known to
persist the alternative format could be useful.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2BMhERRyixhHo55Fr99G0OggGwS6-KiUFx_99earQhqA%40mail.gmail.com.
