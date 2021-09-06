Return-Path: <kasan-dev+bncBDGIV3UHVAGBBKUD3GEQMGQE7UJDVGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AA5D401E40
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 18:28:27 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id z17-20020a05640240d100b003cac681f4f4sf3706000edb.21
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Sep 2021 09:28:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630945707; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q0E6jk8xERbR0CeOtmM6AWqdASj7KNLXplHKab0pqM6gNqEHFxqW68g5X/g5Hoh2wX
         43aQgPjwKUC6ApipJJSXKG5NXOguSBOe3+nEQ8AY9zdxvxufVFRWgC49cBoO/7fMSAz1
         X0+0Ozmb/HzJ6x8+WnHsPgo1d2ldgXpDG6E2ULNcfHOvOmjTdzczTyub/svrR7jevfGe
         FxY2eic3YPElweot3bNXG7V8cFQ6Qnn4WB4pMEPPdqzohST6jO/9eluKDYRxlVF/3OcG
         GmzbTLDKABEDJifFTRl0W1wC3YBJXfyaZgVVjJBstRmI5vgBDKeOjoUkFfNkBLNOGITV
         s0lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=anf1MqraqUXkpkMaF+mHPrn7cxTZtjZTHPOl06q7T04=;
        b=HW2TBbW6yAphtYjWRRxbYKHWWBiiF5GYVNgrm8o4TFMDLbxKQ72jkosc6k6KFUVDlt
         PDuiXCxALJUGPHGMMSDM0+opNBJqGYhrc1hTABcXWFhifac7ThjjlaDPHbHvrha7Y98v
         ixpJ0a78974jGJBV806SVTDaaID9gY1P/81TE/gYXwp0EvYZ6KQ7ICEDUj+kkksZR1GY
         3ojgSqiE7LoKl8VPpoWOmDjEReMqNmB9Ggmwsjhsu48tNEE2Zx01/Udnpi4Hsgp68gA4
         aGgcEQ5RIN6twiUBCY28ttmOqsmWhQFb/iJzlOOPXwrZNNAKXt8hTScVnK+Oz+MBXi7o
         rl7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=2XSfZwPk;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=anf1MqraqUXkpkMaF+mHPrn7cxTZtjZTHPOl06q7T04=;
        b=VZT0g95RnsiCFceBAawk1RrGKDe3ytqdssrEC+XE9QvwH1mX6crkH8Tu80dwgJqBMS
         NQkCn6eFN5wt4bX8HcGhUivZ9LSFJjqi/ygz6NTXu/OcmQ0YKEXmDV1j8mT1gFdwYIo3
         G/cqQChEby9Nxfpow5Lvb9LsmJH+azXhbX/3ChZ1psRLowSpk/YyZ6NdXybi/SaFzgpr
         BGq8Rqychs3lzqP2IOPpqu2EAES7+rwK0Ii962RFmwCXzfg3JITVD44GlI9KZVOi3nu4
         ZExv35GLZTEWveNKAvVpuMPKewxA0OL3cwow3Gr2FdPXqU+OPZ9yDoCh5OTHbwZ29qAm
         Ug5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=anf1MqraqUXkpkMaF+mHPrn7cxTZtjZTHPOl06q7T04=;
        b=eUzQLWu3tuxti9GsmF2Ya7Te71EsrrKdjuqRp+pNAUHTdU3o+SjyFcuHEHO7+6/qA6
         7xF9vP5xzVW31v4SNYre8zjqFvOg0q5x+II7KSRVD9ouMyw+tPnV4iaUC/bJrXjl5CXX
         iGeJ3zgJM2U3xffHxVnfNbF8qFKmnaXdL1EFecJejqFMtl6lS3decrb4GnyEeJR2KBXh
         yv9m4yWGqwaYuGETu9DdMHdTrg4Jjimm71dZz22CGZ1WH5OjGJgvxG8DHKCugXB32jwi
         +Jpq6290wGUdSYEcZOdbG4Ep5z5aXSZhVARRtfS07b/NvSxVoEygY841zhY+T2iH6e3q
         ipjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530U1hb7YfId+naZ8u8oZUf/zrGc19oG3llIiwsPM2oryvcI4zr5
	ZWjrWYoDnvpeAerm6h4t1Nc=
X-Google-Smtp-Source: ABdhPJxIYT1Nx4anjt95zhbQQQWVFjQvQGHxBQw8DLNvoSxZyd0G8CQmhjo6auxHJNVD8bY+cjIjAg==
X-Received: by 2002:a17:906:3a58:: with SMTP id a24mr14089749ejf.109.1630945707171;
        Mon, 06 Sep 2021 09:28:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:361:: with SMTP id rs1ls3342580ejb.4.gmail; Mon, 06
 Sep 2021 09:28:26 -0700 (PDT)
X-Received: by 2002:a17:907:8693:: with SMTP id qa19mr14828362ejc.95.1630945706277;
        Mon, 06 Sep 2021 09:28:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630945706; cv=none;
        d=google.com; s=arc-20160816;
        b=EYe2Hes7yFTUIuSXB92uj6ah59K4ZmWFgZKkgv7dFKrnLjpmUpX4SHcghBDG4zAuUr
         A6CjCPGjEPoQYYMMutuA1dBiGeuZZXIAMkKSdaGqx0maRkcxlGVsh1T7msTm86lMc22o
         xJyKQQAo0yAq08Gn+2SwtYsy8ly0Lkx0cw7015AxyufjyVxrLoYsUwcEZq/wFxL/d2bz
         elY2dnzsvRc4s+GBuWc1dQKFIFiSO0vGJpuDw813MUNuMhUl1HarKwTX4xHrVnGNV7K+
         BEktyv5OX850+CHRVNxLERPEKnzBJzZJ+W84HssLkgcg5HwUjsgfHFvQyKF96vGOVjhD
         G9FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=PB4sDy5RPN525RHq+Yq5F3Pi1PEcR3nel1GIZvo8hVo=;
        b=hy7HFgIh6dgAtL7HhCGrszOpItLHkVEmdc3TBY3dDOtkqCGKynSnUQVThGQdhfNFR2
         adUoRPtoXldr/99ImuN1FMRPOxD0nwM6cxz9c+wb2hxmnlSFwibH4ld0NLwsHqZWdV49
         qPkS8emDOSKM5wZmM7DFF927Is2mSxiH6fxLHR/jbq6Qs/NeiAEZTgHQnljYaS76eqm9
         J+KH689sGtebTR0u2mlJfNX5mzINQxkRZWozWh3dX5MQup1c/akIpx9N3YybhzxHypxL
         1DyU1ycr45N8TQZaHXmBoT3wfrl6HpYN4Fj5ucGOmQaNZKtc0+0Fn/s4i3/udWstZGwN
         6vrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=2XSfZwPk;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id w12si544437edj.5.2021.09.06.09.28.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Sep 2021 09:28:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 6 Sep 2021 18:28:24 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Clark Williams <williams@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH 0/5] kcov: PREEMPT_RT fixup + misc
Message-ID: <20210906162824.3s7tmdqah5i7jnou@linutronix.de>
References: <20210830172627.267989-1-bigeasy@linutronix.de>
 <CANpmjNPZMVkr5BpywHTY_m+ndLTeWrMLTog=yGG=VLg_miqUvQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPZMVkr5BpywHTY_m+ndLTeWrMLTog=yGG=VLg_miqUvQ@mail.gmail.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=2XSfZwPk;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2021-09-06 18:13:11 [+0200], Marco Elver wrote:
> Thanks for sorting this out. Given syzkaller is exercising all of
> KCOV's feature, I let syzkaller run for a few hours with PROVE_LOCKING
> (and PROVE_RAW_LOCK_NESTING) on, and looks fine:
> 
>     Acked-by: Marco Elver <elver@google.com>
>     Tested-by: Marco Elver <elver@google.com>

awesome.

> > One thing I noticed and have no idea if this is right or not:
> > The code seems to mix long and uint64_t for the reported instruction
> > pointer / position in the buffer. For instance
> > __sanitizer_cov_trace_pc() refers to a 64bit pointer (in the comment)
> > while the area pointer itself is (long *). The problematic part is that
> > a 32bit application on a 64bit pointer will expect a four byte pointer
> > while kernel uses an eight byte pointer.
> 
> I think the code is consistent in using 'unsigned long' for writing
> regular pos/IP (except write_comp_data(), which has a comment about
> it). The mentions of 64-bit in comments might be inaccurate though.
> But I think it's working as expected:
> 
> - on 64-bit kernels, pos/IP can be up to 64-bit;
> - on 32-bit kernels, pos/IP can only be up to 32-bit.
> 
> User space necessarily has to know about the bit-ness of its kernel,
> because the coverage information is entirely dependent on the kernel
> image. I think the examples in documentation weren't exhaustive in
> this regard. At least that's my take -- Dmitry or Andrey would know
> for sure (Dmitry is currently on vacation, but hopefully can clarify
> next week).

okay.

> Thanks,
> -- Marco

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210906162824.3s7tmdqah5i7jnou%40linutronix.de.
