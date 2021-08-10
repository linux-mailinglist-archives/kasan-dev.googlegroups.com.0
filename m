Return-Path: <kasan-dev+bncBDAMN6NI5EERBSGHZOEAMGQE5C4DEDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A3DB3E8470
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 22:38:33 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id d16-20020ac25ed00000b02903c66605a591sf59793lfq.15
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 13:38:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628627913; cv=pass;
        d=google.com; s=arc-20160816;
        b=hMJAomeD5bIhWJ4bZNnDdidq5S65vxuTMSqxif6ViSst5oJVSFE47xf+LZ8yJObBtG
         5Dhk6KDeZDty7M5OhjuiV8NqoNDI7h/bjS0V5yTUo7nhDDl0eITvcw/NviAbuu5jzhOn
         CE6CEdxFyDezb3vRyZ66gC6QRwcAkjHHmHq3qErm4nJjnw7bs065ol2bSfgwo3sx3URA
         nlFsmGiqSezj/CkDFtdatDT1TJTtR+SgdQEhQ/OYH86WLIC0gg0Lc0t7bsJBCf7emHug
         MhucALTCErJFKj28Mzfm8cORPUPMFj+a4hdk0PsTrx3J7m4HXnvJT/BNqTBkzD36X0Y3
         TLtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=q6nmzt1lQ4sUoQmD2c3jHRWWEpmzRD122ewtBFaGlf0=;
        b=OKyaCZJnuApVMIexVqQIe7R/9ImcbevP+QtQqk0b0X6/6rFwEUw7H5x/h3ipRkBmwM
         bNMrSsqS9zDh/nx9SfRksyvxPGX4VJjxP8Ro5Pa4aqtKLA/E9hkMmW/82yVmcrHysTwt
         ujwSg8eEYwva2IDeSTNOhCPF0Cq/40RB3DwKoU0t4z4THeivFFYzv44lXKolvQkNgV1V
         TPYudnPCY/D9mnHqQ9Xw8RlIqar9hTWRpMx30r2Q+DugvfKZrcK41MoXkj/Vze0O98si
         uEUjOL8LhG6OfyFE1GuxV24dpfo2n81eIB0i01MGO61ujqCSDmvFtaEGmWWVlX40M8Yw
         d+aQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="Y/oBbb4F";
       dkim=neutral (no key) header.i=@linutronix.de header.b=Yf3Ht3y3;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q6nmzt1lQ4sUoQmD2c3jHRWWEpmzRD122ewtBFaGlf0=;
        b=Bj363vcngjcJUD7KbStqsFwnbdWX03boHkhRqKHd/apBF6mBT9Gw7AP5+e0BR4Q7f5
         utFPwwFi6MjACWGo8pp2t7YSeXtlwQQcvdVJeM9oyoDb719Fw/AVTGWw3S2TOY6DZKfB
         UfpfkDyaeWozLO4NjOp1ilt/AcwypVy0QwEl2eSrRaPqxOCpKhANssRnt+3zzcubqsHA
         u8L/9eDsE2uODKVWYL5bTv5OMsQUujoZVB/VVuRChoE8AIJDmb81pqwEpICwKN/jKC12
         3eh8BvwuENlx1LfpsDvAZqA+1dlExN9SkSoZQ81n8Dw8fqZsLhO/v9p/KFOPOMeS2SJn
         lsRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=q6nmzt1lQ4sUoQmD2c3jHRWWEpmzRD122ewtBFaGlf0=;
        b=KVbRVxuwmICdt5EuwYZ7hbKBp7WL/7eF/SJLXQkU27vCD+o7QPmgRpqLykANiRqlb+
         6nVFO8fl8Ch8PpFnFyYhzcDL2T5qlYgtMAO7zUY7OhZcJ9BN3+NabEN7+K3dw5l7AG+A
         m6tNHqtkg9zoKzmqYvIe79h3O4nXqHs3LRtXLx3yUZtWkj4iynheepkfcWwXjo7b8Ayj
         m4cyiseedNbxfX3MYAX5f1uADojTgd44YnInI+Uyb78VRBz73rvsfcAogAvZeqhN2UJE
         YE3JS+iKXzKAzBAfAVOaOPDZ5+bWn1ziF/jxyaYTPsjAiaSjtQGzXX753zU5xCUkv9X6
         mWEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531pUC3nUMuBIgyJvOLi1UZEost2MN03SeeQUoRTFiMOmkPHsY9u
	gh5IeqDwmMcX8JAC/Nt6/fk=
X-Google-Smtp-Source: ABdhPJw83+uWjMNli7ztyHLZBzD3nYdP/E7hM8PDD9HKUASRi0BnJ8/h+CvnD7sfZ9BBFHaHLp1wAQ==
X-Received: by 2002:a19:ae0a:: with SMTP id f10mr22070611lfc.223.1628627913125;
        Tue, 10 Aug 2021 13:38:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:691e:: with SMTP id e30ls140446lfc.0.gmail; Tue, 10 Aug
 2021 13:38:32 -0700 (PDT)
X-Received: by 2002:a19:4308:: with SMTP id q8mr4506322lfa.179.1628627912149;
        Tue, 10 Aug 2021 13:38:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628627912; cv=none;
        d=google.com; s=arc-20160816;
        b=g+dw5b+DVsD9gUZ0rYW4qCRakAoHzuO9TFjYn6qrqdA6SGDweJfP80JhwDpYFjC7Wk
         46q6oDZqNkE4+jIx7EDaLkE1pYgeFAAfdYGG9QtHUic2hBBxF/mzn8q30Fj2MnHvLzAj
         drfMxY9wEIQNHVAipSOlgSBoPKV+ratBHmBnkNA9Fw2/6J6U/IstyKy4Ptc30ndrja8g
         77NXBG6CdDsxLrNg7jPo7Fo9knbbdlKLq66Quc4YcYhzTbURd0T3qZuKextKLz1JNEfr
         BxTh2DOq/MtXsYg/RxL9xG1OZ651FXF2Hkuv4Ksq6yZ6xp3Qajt2RCh7SgMoSSqFHDmi
         GCvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=PkVtjYm3BfNCg+SbthLRj+WEbFU9jkunNTtXTBea3V4=;
        b=WCPyVjCEPR+XaJ4O4CeMTlB4G7vWczp96xchGXWbQeHdxoZ0llojMtvSOV3ebUBNtv
         6Q+14KX6D+LXra7TzhMqDyYDzmrSIgKWQ7CjGjWCWzXPpeyDilTq4VcJwWgHEsAMlu6J
         BCOjLjeR80eR50F0W+dZjvQG5+vYuTIXTXqytQmytQWvjmmnp/5Q+6Qvr6rTzcT2a3vq
         3+aJod7pJQtMWQijrmN8jCWUXZagiif3jCpYqhu2/bejqDhW4LxHLwJ0FGpBw6cj7Qec
         ZjXoU6Cr3TqVY08/TtN/J7DYqA0fGvGzxft4Urn07z2h7yXGJmzlj8nzoYsS41AC0fNG
         zHGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="Y/oBbb4F";
       dkim=neutral (no key) header.i=@linutronix.de header.b=Yf3Ht3y3;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id v2si799225ljh.8.2021.08.10.13.38.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Aug 2021 13:38:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Clark Williams
 <williams@redhat.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH PREEMPT_RT] kcov:  fix locking splat from
 kcov_remote_start()
In-Reply-To: <20210810095032.epdhivjifjlmbhp5@linutronix.de>
References: <20210809155909.333073de@theseus.lan>
 <20210810095032.epdhivjifjlmbhp5@linutronix.de>
Date: Tue, 10 Aug 2021 22:38:30 +0200
Message-ID: <87sfzhox15.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="Y/oBbb4F";       dkim=neutral
 (no key) header.i=@linutronix.de header.b=Yf3Ht3y3;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1
 as permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Tue, Aug 10 2021 at 11:50, Sebastian Andrzej Siewior wrote:
> On 2021-08-09 15:59:09 [-0500], Clark Williams wrote:
>> Saw the following splat on 5.14-rc4-rt5 with:
> =E2=80=A6
>> Change kcov_remote_lock from regular spinlock_t to raw_spinlock_t so tha=
t
>> we don't get "sleeping function called from invalid context" on PREEMPT_=
RT kernel.
>
> I'm not entirely happy with that:
> - kcov_remote_start() decouples spin_lock_irq() and does local_irq_save()
>   + spin_lock() which shouldn't be done as per
>       Documentation/locking/locktypes.rst
>   I would prefer to see the local_irq_save() replaced by
>   local_lock_irqsave() so we get a context on what is going on.

Which does not make it raw unless we create a raw_local_lock.

> - kcov_remote_reset() has a kfree() with that irq-off lock acquired.

That free needs to move out obviously

> - kcov_remote_add() has a kmalloc() and is invoked with that irq-off
>   lock acquired.

So does the kmalloc.

> - kcov_remote_area_put() uses INIT_LIST_HEAD() for no reason (just
>   happen to notice).
>
> - kcov_remote_stop() does local_irq_save() + spin_lock(&kcov->lock);.
>   This should also create a splat.
>
> - With lock kcov_remote_lock acquired there is a possible
>   hash_for_each_safe() and list_for_each() iteration. I don't know what
>   the limits are here but with a raw_spinlock_t it will contribute to
>   the maximal latency.=20

And that matters because? kcov has a massive overhead and with that
enabled you care as much about latencies as you do when running with
lockdep enabled.

Thanks,

        tglx

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87sfzhox15.ffs%40tglx.
