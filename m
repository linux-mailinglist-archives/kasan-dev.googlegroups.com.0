Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBZNEQOJAMGQEJEJYJEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 211B04E8A28
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 23:08:54 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id m27-20020a2e581b000000b002498087c6f4sf4989732ljb.14
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 14:08:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648415333; cv=pass;
        d=google.com; s=arc-20160816;
        b=l3XC0Ppnhz/w5xkLZ8yBwGmX23zRoTqBlx41xEOHZHc40r2afdvwqf2RyYO/wy8arH
         zQyRwqAjRg3bzGmTY1uISonyxoyuIQkzcWULoP2A7N8/0AD1evMZ54GqXDshOrtYK3QO
         a3crElU3A8OfjVnSwJlhTfit1RFcw7V7AO8Qh9Og4vYyOONZ3Z9fbRNWiREO7yeKyDd/
         vKDuwfsMZI9KhjOQ5XBSukj3ZZUEBdzfLtFsxX25M596OUVdNCvtkIAx1c/bbDF6e5XP
         FRanUsmnwrFyUKC0rHknPNEuCavn75upZwXPcvY/VCI9+59BOy05ULD8/vfQlEEvR0dT
         bRUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=TRd9eKguei+ldzbFCLZ+er8GdFxZzJI/e+jgJSqP//k=;
        b=j1MzAg06SI5lef8P4JP9KAXL4BQfurd8i926IZ8zQ4t0isGSZ7dnPv+VxfVgou7Wzb
         5QjrtaUAlfZvnxaBrhCsoimQ00loetI0cEH+H8IT7vZtC1zTuDmYy+6vZABHpznRf1eU
         1teuRe21d9j5zQszPetMvmL2v5dp5gGiBli2KqyhQArfmcVn+YTeMz32C0n6mfryEKD/
         /Gde2cxLDqT0qcOzPSaYONfMvbI1pHOePrr5fwGa0ZhxcB3LQVtzosT4Rc3fpB0INhVV
         Q07TwOlbpk+KRHnuYrjdN1YAYza7odJDWUjyQqZXuzTAnZ0vrxZAlS3Gjph7eU1uz9WT
         ecaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=TnbXlHjs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TRd9eKguei+ldzbFCLZ+er8GdFxZzJI/e+jgJSqP//k=;
        b=f+lhyt8EfM+CjtdP27jXV2csNkL3+GkbxQ7JtE/IvLxn2vmDie38yN807bgJV9qbxN
         E6I5MPYweh5U8NoQgLfB6sj8T8rNtLTMz580MnBaqUQlQtElIklyaNpvK0Pae/d+xdjI
         wzXxX+HDQeI72qWNqFqOf3pid+Z1xQ7LRiFKLOW0kKS9TQcjiCJljm++8GqWde2N8zjD
         kQjcOFBWzsPcNo2Tu4qEAKOXk9jAh98Zf1sNiVtJAMvbdOkWvgpu9CDCHU7mamIaj9o6
         O8Lkj4aVff1O33qfIJAC5t3xeJR0MQbthJKhe023ZQc++lZbz0fPJaQvDAKrKmFtlRZ3
         +Mxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TRd9eKguei+ldzbFCLZ+er8GdFxZzJI/e+jgJSqP//k=;
        b=It+3Rc+n+WyfsF+zS6qb+pWHWuHOtJY4hQYE8+GpWqpeKG95AF9W1JFfBd6eNJFobE
         PnHrfkR6MDu1BaNsseVKFiV1wQDlJrI8pr61Kv9zvWDO+Hv0cGiZkFst0uCX8EOpHJIC
         Qw5H5DlJCpuVQnHcZvLwOx5dzC8QL3LPQlVyFnp/v78odU/F37ogZ8U4z+3WuVXFXD3F
         l9tID0RrCKgt4DzAUbIxzPNUhxbCBs+/wrRIB3ARecOv1RHZSev9vI/+ErzZN4f1B2p5
         PsWkMBEomn5dBEI3bXo4TtkQNla8bjRJZxSAczmOZ0eqDVUYtRZXJ7a8yWOFuImoCUbc
         nUxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ADoovjiG5UbAzjv2nQOdmWHaUmHv69kDeXZXBo0uLkiPjqQfG
	xDMk01AdcG7NJCQk3VxlPIg=
X-Google-Smtp-Source: ABdhPJySjifoI2q1OjfnASlm+V+O4v4UcF0DVojuJYVq2G2oXZCIpK97PnmthrRK0Kc8dJ50zY+t9A==
X-Received: by 2002:a2e:9212:0:b0:249:84e3:a849 with SMTP id k18-20020a2e9212000000b0024984e3a849mr17480672ljg.158.1648415333474;
        Sun, 27 Mar 2022 14:08:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3813:0:b0:44a:9ec7:d611 with SMTP id f19-20020a193813000000b0044a9ec7d611ls8025lfa.3.gmail;
 Sun, 27 Mar 2022 14:08:52 -0700 (PDT)
X-Received: by 2002:a05:6512:114c:b0:44a:6c26:e58b with SMTP id m12-20020a056512114c00b0044a6c26e58bmr13007879lfg.422.1648415332378;
        Sun, 27 Mar 2022 14:08:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648415332; cv=none;
        d=google.com; s=arc-20160816;
        b=A0mxx+ZeczjxeUrBEz06WFOVGtYKYISFS4ZheOg+rAY4V+x3mmJlkMUiZSWR5f6unm
         wvFAbYrUIOVDaw47PVQXJbbiAr4s+oDr0R/bldZ/NNDDXHmrc+f1YisLXPh9TEAJjR/Z
         FnbK9opgxvNv+Jvsf8+4H6shUt55P664gl1WUC51Fsk1w99fWP7ynT3+kiYGIw2k+3By
         cO9LQqVl8+rxk3XI4lKInFigT3CXJ8rhmRmZdtZWXpMnB9eIXF2GPATq6HpWCGOH8TLz
         o//WV5Kj6kZthgPJb4ZZ7PlkBhOlDvLAxjCOr/g/VqK6mfnl/ICumS1xvwRpbOuqUEvY
         L0bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HsWH6DZnRrNBpmi3G0N/Bk/YRNIz8b7c67Ar9vl8sBo=;
        b=chpy4SajB6phQNuSQZmnPnrXZw5Ju0G7GE0z6bPFKUjYbD9CWpcNfnX3ZINuJfuEKY
         KslFsvB5h3swdbcxKxKw06FPSnTS1dz6VfEZTeDCWCwrgVfIt9qMxKnTzBq6nST8jtTu
         MAXbVcEnNDyLaAgtDIrjF7wsls47dC0SiBGLwmfp3b5upMDJN0xSIJfxNpxuwxxn21jL
         k6fqSDyxl98IeHx9wbObTK0TyJQODl9m2E2lNGhtXbNR8ja2/pwfcB55jVveE1+y2l3a
         wef8xai+RV5pCHXEcfBNWdbBF2GP0Gs+i7Yc3qm3FYS4YREvj79jFdtmISL9xkvTHvSy
         uuUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=TnbXlHjs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id bn35-20020a05651c17a300b002462e02f542si703132ljb.2.2022.03.27.14.08.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Mar 2022 14:08:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id z12so7832784lfu.10
        for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:08:52 -0700 (PDT)
X-Received: by 2002:ac2:5f4d:0:b0:43e:da3e:4529 with SMTP id 13-20020ac25f4d000000b0043eda3e4529mr16949083lfz.627.1648415331743;
        Sun, 27 Mar 2022 14:08:51 -0700 (PDT)
Received: from mail-lf1-f49.google.com (mail-lf1-f49.google.com. [209.85.167.49])
        by smtp.gmail.com with ESMTPSA id y12-20020a2eb00c000000b00249b0547be5sm1353412ljk.99.2022.03.27.14.08.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Mar 2022 14:08:50 -0700 (PDT)
Received: by mail-lf1-f49.google.com with SMTP id bq24so5686717lfb.5
        for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:08:50 -0700 (PDT)
X-Received: by 2002:a05:6512:2296:b0:44a:6aaf:b330 with SMTP id
 f22-20020a056512229600b0044a6aafb330mr13637755lfu.531.1648415329700; Sun, 27
 Mar 2022 14:08:49 -0700 (PDT)
MIME-Version: 1.0
References: <20220327051853.57647-1-songmuchun@bytedance.com>
In-Reply-To: <20220327051853.57647-1-songmuchun@bytedance.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Sun, 27 Mar 2022 14:08:33 -0700
X-Gmail-Original-Message-ID: <CAHk-=wh-mVrp3auBiK2GSMpuqS10Bbq_7fRa6+=zt-0LiF7O2A@mail.gmail.com>
Message-ID: <CAHk-=wh-mVrp3auBiK2GSMpuqS10Bbq_7fRa6+=zt-0LiF7O2A@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm: kfence: fix missing objcg housekeeping for SLAB
To: Muchun Song <songmuchun@bytedance.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, roman.gushchin@linux.dev, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	syzbot <syzbot+f8c45ccc7d5d45fc5965@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=TnbXlHjs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Sat, Mar 26, 2022 at 10:19 PM Muchun Song <songmuchun@bytedance.com> wrote:
>
> The objcg is not cleared and put for kfence object when it is freed, which
> could lead to memory leak for struct obj_cgroup and wrong statistics of
> NR_SLAB_RECLAIMABLE_B or NR_SLAB_UNRECLAIMABLE_B.  Since the last freed
> object's objcg is not cleared, mem_cgroup_from_obj() could return the wrong
> memcg when this kfence object, which is not charged to any objcgs, is
> reallocated to other users.  A real word issue [1] is caused by this bug.

Good that this looks sorted out.

Patch 2/2 seems to still be up in the air. The patch not only causes
build errors, but it looks really very odd to me.

In particular, you do that loop with

                __SetPageSlab(&pages[i]);

in kfence_init_pool(), but that is *not* where you set the
MEMCG_DATA_OBJCGS, and instead do that virt_to_slab(addr) dance later.

That looks very odd to me. I think the two should go hand-in-hand,
since that __SetPageSlab() really is what makes it a slab thing, and I
think it should go together with setting the slab state correctly.

Finally, is there a syzbot report for that second problem?

Anyway, should I apply this PATCH 1/2 now directly as the solution for
the dentry issue, or should I wait for that second patch? They seem to
be related only indirectly, in that the problems were both introduced
by the same commit.

                     Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwh-mVrp3auBiK2GSMpuqS10Bbq_7fRa6%2B%3Dzt-0LiF7O2A%40mail.gmail.com.
