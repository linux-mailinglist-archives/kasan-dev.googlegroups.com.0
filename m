Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQMR2CWAMGQEKXPVB7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 595ED821C1B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 13:59:47 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-6da18672335sf1465701b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 04:59:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704200385; cv=pass;
        d=google.com; s=arc-20160816;
        b=FfXgAM3en30YOjYOB8dETZASD7vmre4hlhmPeKnvbBxR6SQh85g1aRYf10QJ+wKMD9
         H4G2oPeo6EC65cJsjkBW7XOTHIvPd0bM5JyRCKuPLKG8SGi9St0kcCNKC4/zXDH22aVS
         /cDa5LtA+KyqZCj+3Gt0S6KcqpcIKV0lj3FFDpe7fkj8E+rFwFPcNRhuQ7ZByNqu714q
         E/mOsRcqL49EsSxjR7R56kGZ/p3Vn6+1+3ruYWcHbE615Wb/WLPXufPNQIezXBigQQs0
         QYf3APDEs3Pp7Y8LhbxDBgeSYPiF1fBjr2J9nPT+vB2B+WP/3J18fyXS2j2xQ/k6kKC0
         onxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tNYBbYshqJLn8MjTdnVbPtPYwNgI5Sa0nEOL+QZF7+g=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=DMZSpzUaX9YEYExyRBJ60TIX5bvx3DIc2U7cH7WnIcOPWcVHBnFipl4tSXTXeHAgOt
         GJvLHKpNWY3yhstJ+iMDezo+mmKbIRQbwnJf+3oqtf7Xo8FOPzvvtSRZywvou6rv0ZZN
         OcpmKHnj/fj9UNq3uGCn52PgYjvsixlu/PoZWjrYqjs5bvkz7vQSKoe83d35BDbOwUN7
         M8oL3UVFomwMKLR/fhnv1T2wizFOJ0U8R1T/xDgbIlRSVNO5vxRMVFgTLjukYA5+iAbC
         1rP23XUWFxTEu+v5djtJGB/SACmAsgX1vm6u65R7i7pgGx6WYQ16GVDatdMuvQ27BQpG
         XlaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vSKthac/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704200385; x=1704805185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tNYBbYshqJLn8MjTdnVbPtPYwNgI5Sa0nEOL+QZF7+g=;
        b=OVqBjNhvnHFmfDekL/LAIcdTv7Ca/X+n542k6828nhhdx6uGkaM0ansDOevk3bwaT/
         4IEXzrN5UEisrwBuV09SDvUM/Zll46E4Pocp07xP+mrm2mHxx+d9nfU30L11vOrMvrDQ
         isFOt+kKCsSIEmDEFTMcykjPi9AQ7afpUYkzQNUE/mSq4v9s5r+bNeM+GB05IvVN5w8s
         cFjL2HhdtzEp5TuoGDIgWbp7O6bfjO2Lrs1I85+9C5u9v+E6E8fOoR2tOy8temIFJzJi
         TEQH0VvMXyYz0MNbv7YRRfijgfi1TMDnnqdCdd5Pej9urQ7/ldMBgn7mlwQ6UPPRIr0W
         mTpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704200385; x=1704805185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tNYBbYshqJLn8MjTdnVbPtPYwNgI5Sa0nEOL+QZF7+g=;
        b=fVjHYYJbLaPMLFqQBHCzxiiOOJCQwNI7Ng/Y5VLh5C0uVhKXWKq+Xzvx5QMTt5HJDN
         quiTIJUSu1QysS4GrGUYxh68ohmVxfJu+dJQt1grxn7y7UEN5LxBOccq6wlWne4Mm72m
         +pJwaopJU3I9RSDbZzePQrQ9og7OKTc5bZDOx39Ncw+64OoBSG9hvPZ+/mj7bZYUihVq
         Jin1pKFn8Mmp/tAWSwdEcrPjrLVVdDC+zO/fjVlE+/g+xxa60/QFz5YN6WCi4Ji5PeaR
         0PXZmoJVoRF6OB9HZEXTon2x2Tl8GD7blliqMYNObBalA1ErbDBL5DLgDllyBH3QN6I5
         F9dg==
X-Gm-Message-State: AOJu0Yw/s5wneercM/4/57cmJk3aLO5TRZIHGqDw1dJPOvf3pFrwhdEs
	r759rsX+tUZzfXA5HGNNGx0=
X-Google-Smtp-Source: AGHT+IEoLGCdU0vhD+5sR0R4eeLRb+pGfIbvhG3XigE9E86oeQJm7aqEoSSSmt68O+5dERGwoa1zLQ==
X-Received: by 2002:a05:6a20:a987:b0:196:9b97:cd5f with SMTP id cc7-20020a056a20a98700b001969b97cd5fmr1580518pzb.5.1704200385351;
        Tue, 02 Jan 2024 04:59:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f0c:b0:28b:fdf8:19d with SMTP id
 p12-20020a17090a4f0c00b0028bfdf8019dls1407907pjh.1.-pod-prod-01-us; Tue, 02
 Jan 2024 04:59:44 -0800 (PST)
X-Received: by 2002:a17:90a:d715:b0:288:76d7:4227 with SMTP id y21-20020a17090ad71500b0028876d74227mr5159164pju.52.1704200384209;
        Tue, 02 Jan 2024 04:59:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704200384; cv=none;
        d=google.com; s=arc-20160816;
        b=bclTh9bsyHnoBZria/OYf3o/5sNx5YXNEA8cXYD4rYeGRMhwO1WwCqt+4tkFtvc3h5
         hI3kgAMbxDm5m3zyJUET46NF6ymigzCo3kkvDukb8e0r7bpMPOmnrMeSEDw914LIy8l0
         ePhcwRv9WwUTl9nw1BXIyDmk7N7pS9bGI89LrqGSkz9UEm6Ko6TnV7G9qd9/oKPvuyfH
         TOzV2VhWQrJE6o+ZdOeQ2jPOzEZ8pkLfxCQULfpd5/cj3YGS1Cbd+7I2Sv+ZcX++B3Lv
         f18DJtZ89GFX/eJfB+x8mmQCGrEqiXhO0F/qzkuZxfgM9p3V3DsGt3w2CZ0UCW/AHy3Z
         Xw3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GZwVZxl2lOBGt8rlpiCNWllZCCp2YXtPk9YBAjr0+Zo=;
        fh=naLu8b6QNpG3IRa1Sc3pZqeweD+Iq6yOG07UuX+EVok=;
        b=RYIbujw3OT9mQ55g0E72IUYFJp+lfgOLQSzGCC6WE1QcZMpNINsRcaJ/eqUd5yZ4iM
         XU1lXPJX3hC9cuXDurxbPLnRY09S8Dm79JxDeAbwLC/MEge4jeUR4Xxx6PaXHk3/JvVF
         QovBa3YZ3eyJjcCdpdmVIo+j7IaSDPRzzU7QtaotaSVOmcF2ngZkq1QVl2fWOqgqhdcE
         Tiq4WUJtOa3nxgCKFocaQDNH4/D8chFmWNeaDWHCCxxlOTLvZdL1S0NMi9QRg7YuBP8e
         nQTBJ2TEKKoXpUpFpJiFoZ/jYD8CLILA0rFVcrA7c7QbEOeDO4Du3it8uvVQU+DNUADY
         rHPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vSKthac/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2c.google.com (mail-vs1-xe2c.google.com. [2607:f8b0:4864:20::e2c])
        by gmr-mx.google.com with ESMTPS id r2-20020a17090a2e8200b00286998e0d78si798393pjd.1.2024.01.02.04.59.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jan 2024 04:59:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as permitted sender) client-ip=2607:f8b0:4864:20::e2c;
Received: by mail-vs1-xe2c.google.com with SMTP id ada2fe7eead31-467021612acso712658137.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Jan 2024 04:59:44 -0800 (PST)
X-Received: by 2002:a05:6102:9:b0:467:1795:e662 with SMTP id
 j9-20020a056102000900b004671795e662mr4031027vsp.48.1704200382615; Tue, 02 Jan
 2024 04:59:42 -0800 (PST)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
 <ZO8IMysDIT7XnN9Z@elver.google.com> <CA+fCnZdLi3g999PeBWf36Z3RB1ObHyZDR_xS0kwJWm6fNUqSrA@mail.gmail.com>
 <CANpmjNNtT1WUpJu_n5x_tA2sL4+utP0a6oGUzqrU5JuEu3mowg@mail.gmail.com> <CA+fCnZdAUo1CKDK4kiUyR+Fxc_F++CFezanPDVujx3u7fBmw=A@mail.gmail.com>
In-Reply-To: <CA+fCnZdAUo1CKDK4kiUyR+Fxc_F++CFezanPDVujx3u7fBmw=A@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jan 2024 13:59:06 +0100
Message-ID: <CANpmjNNfyKV0Ky=GRiw9_6va3nJMtYejWZJL0tn5cjwXTY8e1Q@mail.gmail.com>
Subject: Re: [PATCH 11/15] stackdepot: use read/write lock
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="vSKthac/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2c as
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

On Wed, 13 Sept 2023 at 19:09, Andrey Konovalov <andreyknvl@gmail.com> wrot=
e:
>
> On Tue, Sep 5, 2023 at 6:19=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> >
> > > Good suggestion. I propose that we keep the rwlock for now, and I'll
> > > check whether the performance is better with percpu-rwsem once I get
> > > to implementing and testing the performance changes. I'll also check
> > > whether percpu-rwsem makes sense for stack ring in tag-based KASAN
> > > modes.
> >
> > I think it's quite obvious that the percpu-rwsem is better. A simple
> > experiment is to measure the ratio of stackdepot hits vs misses. If
> > the ratio is obviously skewed towards hits, then I'd just go with the
> > percpu-rwsem.
> >
> > The performance benefit may not be measurable if you use a small system=
.
>
> I started looking into using percpu-rwsem, but it appears that it
> doesn't have the irqsave/irqrestore API flavor. I suspect that it
> shouldn't be hard to add it, but I'd rather not pursue this as a part
> of this series.
>
> So I still propose to keep the rwlock for now, and switch to
> percpu-rwsem later together with the other perf changes.

I may have gotten lost in the post-vacation email avalanche and missed
it: did you already send the percpu-rwsem optimization? I am a little
worried about the contention the plain rwlock introduces on big
machines.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNfyKV0Ky%3DGRiw9_6va3nJMtYejWZJL0tn5cjwXTY8e1Q%40mail.gmai=
l.com.
