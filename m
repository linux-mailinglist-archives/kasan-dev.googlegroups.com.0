Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBUGQCWQMGQET26A4AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D0CB982B145
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 16:02:31 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-35ff7c81ed9sf5586675ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 07:02:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704985350; cv=pass;
        d=google.com; s=arc-20160816;
        b=nOF3H29JzciL0/qKZHKWWHfW3xdU5TrnwOy0lp2rtwbZHh+xSEJphL2UE3spyp6xKI
         wJ5Y/rxmNZaQXwfg4UK0nHcz5R/E8OrgelEJM9dLr8f2rs1d9dIdBgwgo8sFyRAJ0TA7
         E5AS+qH6Rik+rcqt1CQFPhLfJj9agQuW7QpJhgjU+EdNLZXU39PxrSiQgZxIlN3ItLv7
         K5Laym94J8lC7UvfxM6qIVgBSMtvyFt90ZyAbtlfyJH32qZjkheyLwS+oA/eH0r6USOD
         0jgfPdlkGrkZo7Ilx4Y/zUNvYXt3HsdOtyOC5LJNtAtwU/kTq9D3YGdsFHrM7rUHks/h
         0CmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BLjOPNlXWIfnsJ/6i5FLFDlLDmqptnysPyyljh9jTzY=;
        fh=Bqcihl7FhhVpFXWpzxySx9Zn3csfo0eQL5gD+6pbC+k=;
        b=FfUUYethQiD4QCU21NBvCRF4j2hV6WND51LlKqVi9fPiFgD00mt0rCqnaQavm7/cjT
         7vPQtcCktjedb6qTPueFTBaRFQSKxShDZIO8gohYq3iTfT3aFNAxOd+0BAlsrmurIJXY
         SYo908H++sk+nPqmW+QMEtiQDn7BPcMxf7xBvvePk99/HaMbHy/5/3pCagAbpgrN+lz1
         yz2kGgmHWWx8+QmQlK11CMWL2ayf0/rjoZRQ8yAne1dTzRr2AdqRrE0QzbaShsxLX+v9
         l2UE2dAqeuMJWJP3hOspgbZQ9iXrSpasW+ikSKM8pgVWjDGxdSjvpruHdml3az7Bv549
         8Xiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IU9lxEl2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704985350; x=1705590150; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BLjOPNlXWIfnsJ/6i5FLFDlLDmqptnysPyyljh9jTzY=;
        b=DnzEjFZ0qmXRT/jFW72pp/D6HFx30iLS4sBtum33hLxCoJbNbD9RF84Dfei0kb+Fjx
         m3G4AKsPnjliJ0J5fy0r9znCnVxuobpT540XtZGx6O9XrhRIYCh5sKMcyzds2+7WJaVj
         GZ29NRA8eX1M2df5Vs13JJFmtAv6y+pLRob3uoHqH7b7QhiKetz67JNsaWVGtL2HyJcw
         IWf0yQ77OP6kMgXcdCw+pJVxxyEhF6C+NA75Ngq2E0Ilw794y7K9TbmtN4/B4tFX+xHb
         Jr/QY7qd60Jx9EUI8ZRwycledvgWZX6oHSvSLAb3uymgSLBv7k/znTWDJ6n93A2t4OlO
         +ETQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704985350; x=1705590150;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BLjOPNlXWIfnsJ/6i5FLFDlLDmqptnysPyyljh9jTzY=;
        b=JVWifD7vuxpxDzT3gmeJRYOsKIng9Q5w+u/9nTqDbugziGTE6a9CIFCmDfuoEp36AE
         YwBpRhGW7NULmvLuGkoIiVm2CS8l+gUwm06GvwSSBUCfrF62xIYWFLqXjnEwlxgqzTtB
         Aa9DANQvqlDUIWRcquigSOEf/ZLRXn89aR60E9b0ujV4UfgQ7C7EfNQRm0TWtsNE/k+4
         1oZ6PGrkTKL1i6Rju+uavdVNAGMeywQ3qw/TTelkv+0mKyFwjOZkzQcSYFfk8VMl6cdY
         KLci+DOEsOdOHju4KwkgNrvOfwF4M8kb6CqZCmmLPhEo5hCxM84pI8lcEhlus/DjOoOp
         RcDA==
X-Gm-Message-State: AOJu0Ywhm9zn581wbU5AkrPbOd8rbofWtQInh5iBYQFeOcuzkY2Zhl6j
	NvUsRkknz8kbqWqKxg7fFuc=
X-Google-Smtp-Source: AGHT+IG3AtH/FUW5AKmDiisqP6cqVSFj6q0nnD7HXS+wrpmgBBOVaJp8shduDJk+fVTu4xf2VdUBdA==
X-Received: by 2002:a05:6e02:20c8:b0:35f:b16d:cd64 with SMTP id 8-20020a056e0220c800b0035fb16dcd64mr2601153ilq.0.1704985350419;
        Thu, 11 Jan 2024 07:02:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c52b:0:b0:360:37e3:a84b with SMTP id m11-20020a92c52b000000b0036037e3a84bls2631066ili.0.-pod-prod-04-us;
 Thu, 11 Jan 2024 07:02:29 -0800 (PST)
X-Received: by 2002:a92:c205:0:b0:360:63d6:bc83 with SMTP id j5-20020a92c205000000b0036063d6bc83mr1393262ilo.35.1704985349590;
        Thu, 11 Jan 2024 07:02:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704985349; cv=none;
        d=google.com; s=arc-20160816;
        b=tUF4D913U2HUfSs4+BvEmKbiHwbYZH7gbHMQD3JI5AG4Kq+wsvZSdY+ouNwU5dWqqz
         VVIeehtwE8S15HiKnNaekbyv51k0/8jIW9AUEPT2K8KqvZYHbyyuP9mxdFD5/EmwhIZa
         NMTDsAtFj8b1sr4Bxcy7m/0m6KbeABpVDU5HnylHSix1tQELKdVZ1bxKND8ITY4M4UcZ
         ehemGTKciCvJe3RXWEfPAj+HB78taRx+DBtjxdlcq101/PJSUdsJRD06CjQ7l3f1csC5
         33P7GhmE8zoymh5y3Nvold+vqkwU5gPluuh/lCF9pAU2nUxYjvWdG25jfT8zA+4ttSBT
         unKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AXxf4IYdHRNOCXV3BfrCT7sMwSBwZiXUq0fFiawq+m0=;
        fh=Bqcihl7FhhVpFXWpzxySx9Zn3csfo0eQL5gD+6pbC+k=;
        b=kXT8YKLwldaGLdvOHJpbnmN54ZPG60T4zEM7iRQhIRgLVqTZ3MjM+8RKC8IZIwvepo
         NzUyNwV1gVJTfS+tTawf7BC1RXI6dyzvyzgCAkd0r2h1xDFJwb00UV4z1RIfZgNYw+BH
         SWnjI5h4aC2Ak4SlUSXKZrUnnh2K6cOFj9XfAbqAJbByLv6uBDcCm6h5mXnmWySQlIXp
         D0pbk+84vWViaKbdF5ii7oiCCgQQ8F+jDGU9rejR2ww6thlbWEth1iJG2LFfUJJ0giqT
         iOr1MjCfYbGO2a9oq9YITvcieOAQn8mNGDfSGj6pj1qxiC9FsB/Kww0X8u2CUxRxQ0G5
         FKCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=IU9lxEl2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id z7-20020a056638000700b004667fd6f6besi64711jao.5.2024.01.11.07.02.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jan 2024 07:02:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id 5614622812f47-3bbbf5a59b7so4813231b6e.3
        for <kasan-dev@googlegroups.com>; Thu, 11 Jan 2024 07:02:29 -0800 (PST)
X-Received: by 2002:a05:6808:1152:b0:3bd:59b2:93fd with SMTP id
 u18-20020a056808115200b003bd59b293fdmr321214oiu.68.1704985349083; Thu, 11 Jan
 2024 07:02:29 -0800 (PST)
MIME-Version: 1.0
References: <202401111558.1374ae6f-oliver.sang@intel.com> <b1adbb1c-62b7-459f-a1bb-63774895fbb3@I-love.SAKURA.ne.jp>
In-Reply-To: <b1adbb1c-62b7-459f-a1bb-63774895fbb3@I-love.SAKURA.ne.jp>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Jan 2024 16:01:49 +0100
Message-ID: <CANpmjNNgCt0pByJhEhViyCQXk_9_1a-KfVjQcx4rSFZtuZNe9g@mail.gmail.com>
Subject: Re: [linus:master] [kasan] a414d4286f: INFO:trying_to_register_non-static_key
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: kernel test robot <oliver.sang@intel.com>, Andrey Konovalov <andreyknvl@google.com>, oe-lkp@lists.linux.dev, 
	lkp@intel.com, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=IU9lxEl2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as
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

On Thu, 11 Jan 2024 at 16:00, Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> Commit a414d4286f34 ("kasan: handle concurrent kasan_record_aux_stack calls")
> calls raw_spin_lock_init(&alloc_meta->aux_lock) after __memset() in
> kasan_init_object_meta(), but does not call raw_spin_lock_init() after __memset()
> in release_alloc_meta(), resulting in lock map information being zeroed out?
>
> We should not zero out the whole sizeof(struct kasan_alloc_meta) bytes from
> release_alloc_meta() in order not to undo raw_spin_lock_init() from
> kasan_init_object_meta() ?

Does this fix it:
https://lore.kernel.org/all/20240109221234.90929-1-andrey.konovalov@linux.dev/

> On 2024/01/11 16:29, kernel test robot wrote:
> > [    1.582812][    T0] INFO: trying to register non-static key.
> > [    1.583305][    T0] The code is fine but needs lockdep annotation, or maybe
> > [    1.583887][    T0] you didn't initialize this object before use?
> > [    1.584409][    T0] turning off the locking correctness validator.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b1adbb1c-62b7-459f-a1bb-63774895fbb3%40I-love.SAKURA.ne.jp.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNgCt0pByJhEhViyCQXk_9_1a-KfVjQcx4rSFZtuZNe9g%40mail.gmail.com.
