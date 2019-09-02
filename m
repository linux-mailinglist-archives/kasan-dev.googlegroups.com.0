Return-Path: <kasan-dev+bncBCM2HQW3QYHRBWGZWTVQKGQE54RXAFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id BDF4FA59CA
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 16:53:13 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id j8sf2816729vkn.16
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 07:53:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567435992; cv=pass;
        d=google.com; s=arc-20160816;
        b=jpGoU3ymf4Lo/bA2TT77uDWyZ5oGEFCFyMNDffr43MYEfkvqPdkkNwucR34KRdOpMg
         8Uyv3gEDUYnOddIJm6oj2awABuf6k0Fqa6b7xyaJ/HmG8DkSO+sKW5BQOFF7bbfCBSuz
         RyVO7+6T7lEiAsEVnjVHhi2u/Cypy8s9VAvuQPRNH8HlTu0jpg8iKdt8ANyXKSYPsKEL
         MfD7Ae3lSbYJB/7yQgLU0qDK53ACdSajX1FEsWAQWGtErSZWTBf3t2aJE0+A9Vvg1KIb
         2LL+BVPuEzISyVWMRIYp0fNdBkgquQQip2aPkc2JOLUkw3VXJ8sDkHROXZz0jSpjBbel
         ZiHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:message-id:subject:to:from:date:sender:dkim-signature;
        bh=zu+lj99bP3eGQfQYUzqZaXfryCx9WJk6nkKZModZmdg=;
        b=vvYGvOFEO9CIaAm706rbey9wMsLwpIA/JKdH5SqLCW38GWoD2Bharrd6aOyOrIrart
         8P5M+ra0kb3plcMFBKU8F+jjkBmq6PPufNXWUFieNcDzZWkdE79IH6oMCJ6HZaCT55Fp
         HU89ZMvMmKADvbxeEfXHtPxVGd4d7Wah1iLy4YTAoMicSH9KYBYbU3eRi8MvlhoP88Pw
         hpbCHmvEe6HUtx6AbvyTwi1mPfBA2RuefjIVTgCdfF053ciqLLUq4TmIlFchJSBwgPHp
         ykKqGhWp5nbHaY8Haox4nMxxAGm10IYPKI9y4HO67zAY212spG33PrYqH3fl+eTW9ZUy
         zJYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=GUmHxnbd;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zu+lj99bP3eGQfQYUzqZaXfryCx9WJk6nkKZModZmdg=;
        b=Fes1d+G5D+aWHte+wCcbHJ/z+ne/z9Jaj5BMn7mjPSzWeYRp67eKZ8jEG0mt4kW5+5
         p5hfCwhJuCJ/842+fmdKT9wLHHsYUggQFjTNIo2axDIF5Yk3sWtg2Ukr1O0XC2xsrctl
         IilS44i/pZFjFUP5ZmMWIiE8fzc15BJQvgHoplq0Pg92iuHnnHcrulsLe8Ttz+YhTJKq
         BYH/sbs6riYH9PVM4/HWOILHWDjNKpyk2iYdzdHh1S1wogWjtkMuv/FKofOWsF5fbDYv
         HcVROsqiea9H14Qya6FpL0OddhyNDqA28Qa7L+O6gdriXAkxA2Z91K1K5osb/WQpXKPB
         Z05Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:subject:message-id
         :mime-version:content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zu+lj99bP3eGQfQYUzqZaXfryCx9WJk6nkKZModZmdg=;
        b=XzGDcN8I7ToVuXsGyw5UFlthyJsTbLLeGljruYLbeQHTPRJl13WKfr9psw4/ZupBzc
         RYQQIMXG27elsKj7D4Q4/V2uDo9MT6KISLqudfjAWytSc1mt9pJXLHX2wYuQLctQB3qa
         q1lr1hb/hquls2QIgh736XlRkvoaEIiet0kIlTdVcTxuRr+5yYSq5xw4SMR0sCRpm3WN
         b7lHdvIcaLmYZlT7iLKRJAWBIL5hCQhVp7eJkEgIwITU8Gf+cnzD/2Yg3jyl6roMtodX
         Fbla6aAEgCaYjjoNG+yx+sfY1AryJDjQ8Slv1O4BiDhr6TDrQ+23XtOOyfvb5/heSV0R
         gn8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX73/mXnr0wp6p1FRR6XsIJwWR65ipJJpN3oRFyyJXr2OBlVqG4
	d2DnjgQt3OVeJRjTbgHeMRI=
X-Google-Smtp-Source: APXvYqyqxU5kiDsMCWbNNTZxt/zDRYQJ4BK5gqrqOMHNV/jKz+9R5xBw95iRb8toZQhb64cN4Yu1yg==
X-Received: by 2002:a9f:31cb:: with SMTP id w11mr14246354uad.40.1567435992664;
        Mon, 02 Sep 2019 07:53:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1e5:: with SMTP id 92ls711143ual.8.gmail; Mon, 02 Sep
 2019 07:53:12 -0700 (PDT)
X-Received: by 2002:ab0:6911:: with SMTP id b17mr14419850uas.18.1567435992141;
        Mon, 02 Sep 2019 07:53:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567435992; cv=none;
        d=google.com; s=arc-20160816;
        b=YgwKrJnhwmkzrQrlGn5ao0JSp+TWMZvOoUkrykjz/1qjh6a5RR+zYqRd5sa6WdrUwv
         tzAcdiSA35nSS0FEdFO+5vyeGRl018PP7tTLh7yPNK+cA+MGJIM/TrLFDmGws4EzvQ5H
         ZcUL6bIcCwa7Pdw/LZG8fnuIMMsIyfKLsSePe07Z4wUc0xLuEp3KQI+RBqfIL/jghOVf
         5pFwaARgTGjhdiwP7CZn6APoWwciA674Bw2Ofu8VwKpWbWqlOuJULkU6MxRyWPrZ+VO/
         RHHrnNWJKcL6M1Y0pMX/hR24Jrk06DBTyA/Rl+Loub+ZQMHjqQCFEHl2hHABKVET+4NY
         tAIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:to
         :from:date:dkim-signature;
        bh=rVLxT8ezqTMwsv/VJ6c7IQqkJYX0b7EWJ92OW94HFnU=;
        b=tsoaStWYoWljFH5Fwc2Qgikhp5F00Z/DiorKOjai8vkA6q5kMAAmlphyc3hoCxcokc
         2oQ/N8JNbBT0IIAuzW6QqxQA5N6CGfavX9KZM3gMD9E4+3SvGif1FU+/I3JijxUmRrXR
         Isn2Lc3wO/q8LdAfOVX+cLURbIMnsoqNR7ZyOBIsYoCiZxPzkx7sJf8GvE5pot5xURqo
         ydt4GuGcBhcP1g/3DAj8SscAhNYwIegeW1sWv0AshWgT4C2jTOLzA3ZMaz1u30czb4vq
         YHqMS/aieT9sL2JM6tsBp6zSo6fr0dggyod3H0NAghdR/IsRYGFp+dBxTFJspLSUt8mG
         fHrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=GUmHxnbd;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id d4si285805uam.0.2019.09.02.07.53.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2019 07:53:11 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92 #3 (Red Hat Linux))
	id 1i4nhe-0001rP-Qd
	for kasan-dev@googlegroups.com; Mon, 02 Sep 2019 14:53:10 +0000
Date: Mon, 2 Sep 2019 07:53:10 -0700
From: Matthew Wilcox <willy@infradead.org>
To: kasan-dev@googlegroups.com
Subject: Better stack traces for RCU-delayed freeing
Message-ID: <20190902145310.GD2431@bombadil.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.11.4 (2019-03-13)
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=GUmHxnbd;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
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


This is from a syzbot report of use-after-free:

Freed by task 26359:
 save_stack+0x23/0x90 mm/kasan/common.c:69
 set_track mm/kasan/common.c:77 [inline]
 __kasan_slab_free+0x102/0x150 mm/kasan/common.c:455
 kasan_slab_free+0xe/0x10 mm/kasan/common.c:463
 __cache_free mm/slab.c:3425 [inline]
 kmem_cache_free+0x86/0x320 mm/slab.c:3693
 shmem_free_in_core_inode+0x63/0xb0 mm/shmem.c:3640
 i_callback+0x44/0x80 fs/inode.c:216
 __rcu_reclaim kernel/rcu/rcu.h:222 [inline]
 rcu_do_batch kernel/rcu/tree.c:2114 [inline]
 rcu_core+0x67f/0x1580 kernel/rcu/tree.c:2314
 rcu_core_si+0x9/0x10 kernel/rcu/tree.c:2323
 __do_softirq+0x262/0x98c kernel/softirq.c:292

I'd really like to know how we came to call destroy_inode() which calls

        call_rcu(&inode->i_rcu, i_callback);

Is there some way we could capture that stacktrace at call_rcu()
time and add that to the stacktrace reported here?  We could have a
call_rcu_freeing() macro and manually annotate the ones which are going
to free memory (I suspect that's most call_rcu() sites to be honest).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902145310.GD2431%40bombadil.infradead.org.
