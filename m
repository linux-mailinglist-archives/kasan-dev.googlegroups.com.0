Return-Path: <kasan-dev+bncBDW2JDUY5AORBQWJ4WPAMGQEQ5FUNBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E6DD46835DA
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 19:58:11 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id 12-20020a62160c000000b005808c2cd0b6sf7669496pfw.12
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 10:58:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191490; cv=pass;
        d=google.com; s=arc-20160816;
        b=FaRAPYoxUcIPKIdRP2OO8/netcHMLH/EbNnL7WWeghaUsLxbeVfCSONA1jdNvlH6AR
         R17VlyIGggdn4w5Y+uaI+tzOfdXvTWru2ovCwli8XPKMSTODpoUzBYwGJ68mqnNeWpmz
         CCHOk5j5XYSUEfdZyMRUM5weztSj6t1WSCDmEpS1d0lRR8Z+PBL3z/9TQS8BjrCi07vn
         QYL9FfIQUh3C29bkqtm6oQZYiUfA1rkk30aMjxNBA5/1E9hafOmhQ0pvZhbS31nTJoIL
         PZk765A3Hx+gxLZso9ag45AlOoZZZhi6xvLbBpuerlDFTYnxWzkIOJJMSm5FlSlsWygo
         B0/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MxLqljiun3tD7aXgKvsqMGKmnvcj5Wtg6wSzGJIKyM8=;
        b=jou+U7AfkJPyIYtNP/RCrN1X4Y2nXY1hdnkiD8icLjSJjS6XMwaNvg17dt3q+7moxJ
         Qq7Y0xcNjBWSOuw16qsvukcHR3Dalr3n6VvOam2mJpIuETMcfuTcXV+yEzKjgwTGS0bU
         o36QZpLw1Xp3K+JlTxaAy3cCigxGitKwld7eOXjLQ/LntOc4kLq2g77aQLkO3hbAv4QS
         CTljglfIbh1MG43rGNgntVKoHPxhfgEXEZr6iZXXcDrUJDbrph2P5K9rRJz3EGh2cpt2
         vqPqgJ9kkF+eatxgpRj4ps2WU+0Gj8jVA15f73zwx1cayfGksNlxKpjpiwqLj6hL8gsP
         tvZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dou2Jilz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MxLqljiun3tD7aXgKvsqMGKmnvcj5Wtg6wSzGJIKyM8=;
        b=OxO44Uvn025DEYH8itm0kNJNEJ1jgFnx1sxNQQhItPaOz3qcUfkJtxpsaVmWrgEfet
         G5UDGz4/IIsFD3bPlG6j59u3NmVvxT0/GPOPj6TX9HV85ztH8Ochjhv10FmxBu68lnWI
         UK5Lcj1kNzS6gAtZWXLc1wNudCAD/IPBROM03xF/okKsAKlEI7F3xtejLIqQVONeaDPL
         XZrukYMjsX2zJWvZVnzNqQ64LLwWT791kXVj8433gzPasxaB95BKjmUyRoI7DlGYgPqI
         S1GamLCBf9XKhJr7hodY83874Fw+a1V9Etmk9rAxDzZrcaUxvhu/tEOP+9LuSFHoSAFh
         +u5w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=MxLqljiun3tD7aXgKvsqMGKmnvcj5Wtg6wSzGJIKyM8=;
        b=gak/+1ZTogmnP6G1t1oCARfJ6eYGiUqlGAmHRLrEz+/Gz+aqokUc4k2PVAcFhlGJFK
         EorzRHzPywdZAM+ObbnrYsmNvnsOFVQ3oJkMq/HPpG70B4hdVIBR0q46Q/9Ju5mBT1RC
         zjWVZbd83b5N2pyPVFBo+tuDQAs2y3RRamA+GB02xNNeu0xIm0wdFR0qP13LymkY6oO9
         UnlsBbPpnWfCo1KXqLwtux8f4hqp0e4JOlCGZbLdkhscWWlAras5UVyNeAOt40wI+OgF
         BaDjU5kS+OiFKPiGChbadZvjYpnztzUPiKki4DjtfVl60+a81wKI8pNSse580pqfaL4v
         cxHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MxLqljiun3tD7aXgKvsqMGKmnvcj5Wtg6wSzGJIKyM8=;
        b=jACC7xne9HiiqESbmyF83okjT7yy4NeAmkypYGXthxxAo6dfVkaTAZwanWCVzd0LQY
         A1lu1uPRI8OeRupEfZ2m9e2wBmQZQs7f+Lewx8Raa5phdPF1USab4txzWtEUaJOb5UNf
         O9SecwmV0RoalTlrN1EGiKO8jYKdBr62UBPxFBMpI1Hc/eJL1xjByK7/kVu0Ksr7+Gtg
         YrCo8iWIZN9jY2VXEVuQ5QPTM3M1oXo9sXYrXKAspsRFHQ7D8Zxs10R7N9pJPM/JtEgR
         mFexCVwQ41y2kN+NBn0pyU4uQxrQYCeq7KQ1ur1eR2Fx3KnIxMEKRAyIekD611XNu+eL
         i2kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWyNQ7iZeIo/lBiKfxDCB2vQAvJHUeSUQxSnhaPwmzfShObGxTz
	Qp5qi6S5FxrUD7Qezbr+zk8=
X-Google-Smtp-Source: AK7set8XjkOMnC1m2zb+re7LgeE4KHAuptON6bE4rJP3TLKYqkUuf9qyDGuyQHwcD6x1OkUTBFF9Bw==
X-Received: by 2002:a17:90b:3552:b0:230:d3e:ccf1 with SMTP id lt18-20020a17090b355200b002300d3eccf1mr866291pjb.66.1675191490300;
        Tue, 31 Jan 2023 10:58:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:8bca:0:b0:475:7659:869 with SMTP id j193-20020a638bca000000b0047576590869ls3802376pge.6.-pod-prod-gmail;
 Tue, 31 Jan 2023 10:58:09 -0800 (PST)
X-Received: by 2002:aa7:9511:0:b0:593:dc6d:53ab with SMTP id b17-20020aa79511000000b00593dc6d53abmr5152192pfp.27.1675191489528;
        Tue, 31 Jan 2023 10:58:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191489; cv=none;
        d=google.com; s=arc-20160816;
        b=L2EyTThVGTH9ltgBCoMYzJ7Mvl/EZYcjqryvE8G8QFikNetSAQ4dE4szzLfpWX3PwZ
         1fd4jZqnrjjCkE1cpydWowjirYfVFeUJw+lRtjA+HvCOheThFJmAQZt+EMTca64UPob5
         u7l05AyJCo+lzSOrtDbtHkZFeOZf7DUQGXzHoIsxqBlph6d6FwOwoGYbyu3uFJQJv4uv
         hkUV5Y4QLiL7qvvjiISYuyvWlkMctvbHfcNSHi/TkPhh5ifk9t+ae5xq/Qc8+wY3AqbQ
         5dk9JwXwFCdCLUM8usffu8fXckycI0MzmNdyLyBDAlKXcBMFmZGgDj8sjtXKka8ZzFTT
         fhew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bCWK8k8m5VD33jjUoYPOLmfdpETQJTETp3AURhGUsTI=;
        b=kmDQ2fXVGIcvDMdOSP0fasv+wrQuJpB1Ddm2Zsm3n/CB1DfLYFLUimwxj+39uebEiz
         ETXDX0/xlREAk7e1CKI23CFsAkWKEpRCKVDpnOM4JPxy8HpRCF0EaaRurEQJl1V7jLvn
         ERgDTiL2tQ6ls6ILeiPPaghk3rBFj4oVr6muio9UTmvEyh8i2CfUQ3qto+YGe5UCMhCb
         5Pdv0dEHHdlLBd9j+LoZHbNUj7IMZdqOkXcC3eJQWslcsuHJ11zbQPr8wijAvqsrPHdR
         e0R5/VkEoNFOMV+xwl28IOGLlxhLqrdypSrifdYsbfkObcNpytmlxdRGUARoSi8EgPvO
         ihag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dou2Jilz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id o191-20020a62cdc8000000b0059076272a23si1231835pfg.3.2023.01.31.10.58.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 10:58:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id 144so10902160pfv.11
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 10:58:09 -0800 (PST)
X-Received: by 2002:a05:6a00:9aa:b0:593:e0ce:fc20 with SMTP id
 u42-20020a056a0009aa00b00593e0cefc20mr1061238pfg.28.1675191489136; Tue, 31
 Jan 2023 10:58:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <19512bb03eed27ced5abeb5bd03f9a8381742cb1.1675111415.git.andreyknvl@google.com>
 <CANpmjNNzNSDrxfrZUcRtt7=hV=Mz8_kyCpqVnyAqzhaiyipXCg@mail.gmail.com>
In-Reply-To: <CANpmjNNzNSDrxfrZUcRtt7=hV=Mz8_kyCpqVnyAqzhaiyipXCg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 19:57:58 +0100
Message-ID: <CA+fCnZdwuAm-fD-o2Yq86=NgU=YympuwAmERN9KwjpYfkPeYLg@mail.gmail.com>
Subject: Re: [PATCH 16/18] lib/stackdepot: annotate racy slab_index accesses
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dou2Jilz;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jan 31, 2023 at 9:41 AM Marco Elver <elver@google.com> wrote:
>
> > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > index f291ad6a4e72..cc2fe8563af4 100644
> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -269,8 +269,11 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
> >                         return NULL;
> >                 }
> >
> > -               /* Move on to the next slab. */
> > -               slab_index++;
> > +               /*
> > +                * Move on to the next slab.
> > +                * WRITE_ONCE annotates a race with stack_depot_fetch.
>
> "Pairs with potential concurrent read in stack_depot_fetch()." would be clearer.
>
> I wouldn't say WRITE_ONCE annotates a race (race = involves 2+
> accesses, but here's just 1), it just marks this access here which
> itself is paired with the potential racing read in the other function.

Will do in v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdwuAm-fD-o2Yq86%3DNgU%3DYympuwAmERN9KwjpYfkPeYLg%40mail.gmail.com.
